import { verifyCrossStationEventProof } from './offlineCrypto';
import {
  BLUEPRINT_LIMITS,
  type AcceptanceProof,
  type CrossStationEventProof,
  type OfflinePendingEvent,
  type StationCertificate,
  type TaiPackage,
  type TraceEvent,
} from '../types/tai';

export interface ImportedBatchPayload {
  format?: string;
  exportedAt?: string;
  operatorUid?: string;
  operatorEmail?: string;
  deviceId?: string;
  stationKeyId?: string;
  stationPublicKeyB64u?: string;
  stationCert?: StationCertificate | null;
  events?: unknown[];
}

export interface RejectedBatchEvent {
  eventId: string;
  reason: string;
}

export interface VerifiedBatchResult {
  validEvents: OfflinePendingEvent[];
  rejectedEvents: RejectedBatchEvent[];
}

function isTransferEventType(val: string): val is 'dispatch' | 'receive' | 'return' {
  return val === 'dispatch' || val === 'receive' || val === 'return';
}

/**
 * Cryptographically verifies every event inside an exported offline batch (.json):
 * - Validates schema & bounds
 * - Validates station certificate (if issued by a trusted platform key)
 * - Verifies receiver ECDSA P-256 acceptance signature
 * - Verifies station ECDSA P-256 signature over ciphertext, IV, AuthTag, timestamp, and nonce
 */
export async function verifyImportedOfflineBatch(
  parsed: ImportedBatchPayload,
  options?: {
    trustedIssuerKeyIds?: string[];
    trustedStationKeyIds?: string[];
    requireStationCert?: boolean;
  }
): Promise<VerifiedBatchResult> {
  if (!parsed || parsed.format !== 'tai-offline-batch-v1' || !Array.isArray(parsed.events)) {
    return {
      validEvents: [],
      rejectedEvents: [{ eventId: 'BATCH', reason: 'Formato de lote inválido.' }],
    };
  }

  const validEvents: OfflinePendingEvent[] = [];
  const rejectedEvents: RejectedBatchEvent[] = [];

  for (const rawItem of parsed.events) {
    if (!rawItem || typeof rawItem !== 'object') {
      rejectedEvents.push({ eventId: 'UNKNOWN', reason: 'Entrada vacía o malformada.' });
      continue;
    }

    const r = rawItem as Record<string, unknown>;
    const eventId = typeof r.eventId === 'string' ? r.eventId.slice(0, BLUEPRINT_LIMITS.EVENT_ID_MAX) : 'UNKNOWN';
    const evtType = String(r.eventType || '');
    const seal = String(r.sealStatus || 'intact');

    if (
      typeof r.eventId !== 'string' ||
      typeof r.packageId !== 'string' ||
      typeof r.acceptanceNonce !== 'string' ||
      typeof r.cvvCiphertext !== 'string' ||
      typeof r.cvvIv !== 'string' ||
      typeof r.cvvAuthTag !== 'string' ||
      typeof r.csgSeal !== 'string' ||
      !isTransferEventType(evtType)
    ) {
      rejectedEvents.push({ eventId, reason: 'Faltan campos criptográficos o de trazabilidad obligatorios.' });
      continue;
    }

    const candidateProof = (r.proof as CrossStationEventProof | undefined) || undefined;
    const normalizedProof: CrossStationEventProof | undefined = candidateProof
      ? {
          ...candidateProof,
          stationCert: candidateProof.stationCert || parsed.stationCert || undefined,
        }
      : undefined;

    const candidate: OfflinePendingEvent = {
      localId: String(r.localId || `IMP_${Date.now()}_${validEvents.length}`).slice(0, 64),
      eventId,
      packageId: r.packageId.slice(0, BLUEPRINT_LIMITS.ID_MAX),
      packageCode: String(r.packageCode || r.packageId).slice(0, BLUEPRINT_LIMITS.CODE_MAX),
      eventType: evtType,
      delivererName: String(r.delivererName || 'Operador offline').slice(0, BLUEPRINT_LIMITS.AREA_MAX),
      receiverName: String(r.receiverName || 'Receptor offline').slice(0, BLUEPRINT_LIMITS.AREA_MAX),
      zone: String(r.zone || 'Centro Logístico Buenos Aires').slice(0, BLUEPRINT_LIMITS.AREA_MAX),
      functionRole: String(r.functionRole || 'Operador').slice(0, BLUEPRINT_LIMITS.AREA_MAX),
      observations: String(r.observations || '').slice(0, BLUEPRINT_LIMITS.OBS_MAX),
      acceptanceNonce: r.acceptanceNonce.slice(0, BLUEPRINT_LIMITS.NONCE_MAX),
      offlineSequence: typeof r.offlineSequence === 'number' ? r.offlineSequence : 1,
      deviceId: String(r.deviceId || parsed.deviceId || 'DEV_OFFLINE_HTML').slice(0, 64),
      localTimestamp: String(r.localTimestamp || new Date().toISOString()).slice(
        0,
        BLUEPRINT_LIMITS.TIMESTAMP_MAX
      ),
      sealStatus: seal === 'opened' || seal === 'damaged' ? seal : 'intact',
      discrepancyNote: String(r.discrepancyNote || '').slice(0, BLUEPRINT_LIMITS.DISCREPANCY_MAX),
      cvvCiphertext: r.cvvCiphertext.slice(0, BLUEPRINT_LIMITS.CIPHER_MAX),
      cvvIv: r.cvvIv.slice(0, BLUEPRINT_LIMITS.SHORT_HEX_MAX),
      cvvAuthTag: r.cvvAuthTag.slice(0, BLUEPRINT_LIMITS.SHORT_HEX_MAX),
      csgSeal: r.csgSeal.slice(0, BLUEPRINT_LIMITS.CSG_MAX),
      ...(normalizedProof?.acceptanceProof
        ? {
            acceptanceHash: normalizedProof.acceptanceProof.acceptanceHash.slice(
              0,
              BLUEPRINT_LIMITS.HASH_MAX
            ),
            acceptanceCryptoId: normalizedProof.acceptanceProof.acceptanceCryptoId.slice(
              0,
              BLUEPRINT_LIMITS.CRYPTO_ID_MAX
            ),
            receiverUid: normalizedProof.acceptanceProof.receiverUid.slice(0, BLUEPRINT_LIMITS.ID_MAX * 2),
            receiverKeyId: normalizedProof.acceptanceProof.receiverKeyId.slice(
              0,
              BLUEPRINT_LIMITS.KEY_ID_MAX
            ),
            receiverSignature: normalizedProof.acceptanceProof.signatureB64u.slice(
              0,
              BLUEPRINT_LIMITS.SIG_MAX
            ),
          }
        : {}),
      ...(normalizedProof ? { proof: normalizedProof } : {}),
    };

    const verifyRes = await verifyCrossStationEventProof(candidate, normalizedProof, {
      trustedIssuerKeyIds: options?.trustedIssuerKeyIds,
      trustedStationKeyIds: options?.trustedStationKeyIds,
      requireStationCert: options?.requireStationCert ?? false,
    });

    if (!verifyRes.valid) {
      rejectedEvents.push({ eventId: candidate.eventId, reason: verifyRes.reason });
      continue;
    }

    validEvents.push(candidate);
  }

  return { validEvents, rejectedEvents };
}

export type TransferIdempotencyDecision =
  | { status: 'already_synced'; existingEventId: string }
  | { status: 'duplicate_qr_conflict'; reason: string }
  | { status: 'sequence_conflict'; reason: string }
  | { status: 'new_valid' };

/**
 * Pure idempotency and conflict classifier for transfer events.
 * Prevents retried partial syncs from converting already-committed events into false conflicts.
 */
export function evaluateTransferIdempotency(params: {
  existingEvents: Array<
    Pick<
      TraceEvent,
      'id' | 'acceptanceNonce' | 'csgSeal' | 'capturedOffline' | 'offlineSequence' | 'cvvState'
    >
  >;
  acceptanceNonce: string;
  capturedOffline: boolean;
  offlineSequence: number;
  preSealed?: {
    eventId: string;
    csgSeal: string;
  };
}): TransferIdempotencyDecision {
  // 1. Idempotent match: same eventId OR same (acceptanceNonce + csgSeal)
  const alreadyCommitted = params.existingEvents.find(
    (ev) =>
      (params.preSealed?.eventId && ev.id === params.preSealed.eventId) ||
      (ev.acceptanceNonce === params.acceptanceNonce &&
        Boolean(params.preSealed?.csgSeal) &&
        ev.csgSeal === params.preSealed?.csgSeal)
  );
  if (alreadyCommitted) {
    return { status: 'already_synced', existingEventId: alreadyCommitted.id };
  }

  // 2. Genuine replay conflict: different event reusing an already-committed acceptanceNonce
  const duplicateNonce = params.existingEvents.find(
    (ev) => ev.acceptanceNonce === params.acceptanceNonce
  );
  if (duplicateNonce) {
    return {
      status: 'duplicate_qr_conflict',
      reason: `QR de aceptación duplicado (${params.acceptanceNonce}). Ya fue usado por el evento ${duplicateNonce.id}.`,
    };
  }

  // 3. Incompatible offline sequence
  const hasIncompatibleOffline =
    params.capturedOffline &&
    params.existingEvents.some(
      (ev) =>
        ev.capturedOffline &&
        ev.offlineSequence >= params.offlineSequence &&
        ev.cvvState === 'valid'
    );
  if (hasIncompatibleOffline) {
    return {
      status: 'sequence_conflict',
      reason: `Conflicto de secuencia offline (#${params.offlineSequence}). Requiere revisión del supervisor.`,
    };
  }

  return { status: 'new_valid' };
}

export interface SyncBatchSummary {
  synced: number;
  alreadySynced: number;
  conflicts: number;
  failed: number;
  remaining: OfflinePendingEvent[];
  lastError?: string;
}

/**
 * Processes an offline queue event-by-event, invoking `onQueueProgress` immediately
 * after each confirmed item so partial network failures never retain already-synced items.
 */
export async function syncOfflineQueueBatch(params: {
  queue: OfflinePendingEvent[];
  packages: TaiPackage[];
  uploadItem: (
    item: OfflinePendingEvent,
    pkg: TaiPackage
  ) => Promise<{ duplicateOrConflict: boolean; alreadySynced?: boolean; reason?: string }>;
  onQueueProgress: (nextQueue: OfflinePendingEvent[]) => Promise<void> | void;
}): Promise<SyncBatchSummary> {
  let workingQueue = [...params.queue];
  let synced = 0;
  let alreadySynced = 0;
  let conflicts = 0;
  let failed = 0;
  let lastError: string | undefined;

  const blockedPackageIds = new Set<string>();

  for (const item of params.queue) {
    if (blockedPackageIds.has(item.packageId)) {
      continue;
    }

    const pkg = params.packages.find((p) => p.id === item.packageId);
    if (!pkg) {
      // Package metadata missing (e.g. deleted or belongs to another account); keep item untouched
      continue;
    }

    try {
      const res = await params.uploadItem(item, pkg);
      if (res.alreadySynced) {
        alreadySynced += 1;
      } else if (res.duplicateOrConflict) {
        conflicts += 1;
      } else {
        synced += 1;
      }

      // Immediately remove confirmed event from workingQueue and persist before advancing
      workingQueue = workingQueue.filter((q) => q.eventId !== item.eventId);
      await params.onQueueProgress([...workingQueue]);
    } catch (err) {
      failed += 1;
      blockedPackageIds.add(item.packageId);
      lastError = err instanceof Error ? err.message : String(err);
      workingQueue = workingQueue.map((q) =>
        q.eventId === item.eventId
          ? {
              ...q,
              retryCount: (q.retryCount ?? 0) + 1,
              lastSyncError: lastError,
            }
          : q
      );
      await params.onQueueProgress([...workingQueue]);
    }
  }

  return {
    synced,
    alreadySynced,
    conflicts,
    failed,
    remaining: workingQueue,
    ...(lastError ? { lastError } : {}),
  };
}

export type { AcceptanceProof };
