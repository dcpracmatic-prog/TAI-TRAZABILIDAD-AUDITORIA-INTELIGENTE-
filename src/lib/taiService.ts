import {
  collection,
  doc,
  getDoc,
  getDocs,
  onSnapshot,
  orderBy,
  query,
  serverTimestamp,
  setDoc,
  updateDoc,
  where,
  writeBatch,
} from 'firebase/firestore';
import { db, handleFirestoreError, OperationType } from './firebase';
import {
  type AuditAction,
  type AuditLog,
  type AuditSeverity,
  BLUEPRINT_LIMITS,
  type IdentificationStatus,
  type LifecycleStatus,
  type OfflinePendingEvent,
  type PilotConfig,
  type SealStatus,
  type TaiPackage,
  type TraceEvent,
  type TraceEventType,
} from '../types/tai';

function sanitizeId(raw: string, maxLen: number): string {
  const cleaned = raw.replace(/[^a-zA-Z0-9_-]/g, '_').slice(0, maxLen);
  return cleaned.length >= 3 ? cleaned : `tai_${Date.now()}`;
}

function clampStr(val: string, maxLen: number, fallback = ''): string {
  const s = (val ?? fallback).trim();
  return s.slice(0, maxLen);
}

export function generatePackageId(): string {
  const suffix = Math.random().toString(36).slice(2, 7).toUpperCase();
  return `PKG_BA_${Date.now().toString(36).toUpperCase()}_${suffix}`;
}

export function generateEventId(prefix = 'EVT'): string {
  const suffix = Math.random().toString(36).slice(2, 7).toUpperCase();
  return `${prefix}_${Date.now().toString(36).toUpperCase()}_${suffix}`;
}

export function generateNonce(): string {
  return `NONCE_${Math.random().toString(36).slice(2, 10).toUpperCase()}_${Date.now().toString(36).toUpperCase()}`;
}

async function sealEventOnServer(params: {
  packageId: string;
  eventId: string;
  eventType: TraceEventType;
  delivererName: string;
  receiverName: string;
  zone: string;
  functionRole: string;
  acceptanceNonce: string;
  localTimestamp: string;
  observations: string;
}): Promise<{
  ciphertext: string;
  iv: string;
  authTag: string;
  csgSeal: string;
}> {
  const res = await fetch('/api/crypto/seal', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(params),
  });
  if (!res.ok) {
    const body = await res.json().catch(() => ({}));
    throw new Error(body.error || 'No se pudo emitir el sellado AES-256-GCM / CSG.');
  }
  return res.json();
}

export function subscribeUserPackages(
  userId: string,
  onData: (packages: TaiPackage[]) => void,
  onError?: (err: Error) => void
) {
  const path = 'packages';
  const q = query(
    collection(db, path),
    where('ownerId', '==', userId),
    orderBy('updatedAt', 'desc')
  );
  return onSnapshot(
    q,
    (snapshot) => {
      const items = snapshot.docs.map((d) => d.data() as TaiPackage);
      onData(items);
    },
    (error) => {
      try {
        handleFirestoreError(error, OperationType.LIST, path);
      } catch (e) {
        if (onError && e instanceof Error) onError(e);
      }
    }
  );
}

export function subscribePackageEvents(
  packageId: string,
  userId: string,
  onData: (events: TraceEvent[]) => void,
  onError?: (err: Error) => void
) {
  const path = `packages/${packageId}/events`;
  const q = query(
    collection(db, path),
    where('ownerId', '==', userId),
    orderBy('createdAt', 'desc')
  );
  return onSnapshot(
    q,
    (snapshot) => {
      onData(snapshot.docs.map((d) => d.data() as TraceEvent));
    },
    (error) => {
      try {
        handleFirestoreError(error, OperationType.LIST, path);
      } catch (e) {
        if (onError && e instanceof Error) onError(e);
      }
    }
  );
}

export function subscribeAuditLogs(
  userId: string,
  onData: (logs: AuditLog[]) => void,
  onError?: (err: Error) => void
) {
  const path = 'auditLogs';
  const q = query(
    collection(db, path),
    where('ownerId', '==', userId),
    orderBy('createdAt', 'desc')
  );
  return onSnapshot(
    q,
    (snapshot) => {
      onData(snapshot.docs.map((d) => d.data() as AuditLog));
    },
    (error) => {
      try {
        handleFirestoreError(error, OperationType.LIST, path);
      } catch (e) {
        if (onError && e instanceof Error) onError(e);
      }
    }
  );
}

export async function loadPilotConfig(userId: string): Promise<PilotConfig | null> {
  const path = `pilotConfigs/${userId}`;
  try {
    const snap = await getDoc(doc(db, 'pilotConfigs', userId));
    return snap.exists() ? (snap.data() as PilotConfig) : null;
  } catch (error) {
    handleFirestoreError(error, OperationType.GET, path);
  }
}

export async function savePilotConfig(
  userId: string,
  input: Omit<PilotConfig, 'ownerId' | 'updatedAt'>
): Promise<void> {
  const path = `pilotConfigs/${userId}`;
  const payload = {
    ownerId: userId,
    solverOrg: clampStr(input.solverOrg, BLUEPRINT_LIMITS.ORG_MAX),
    boxSupplier: clampStr(input.boxSupplier, BLUEPRINT_LIMITS.ORG_MAX),
    trlLevel: clampStr(input.trlLevel, BLUEPRINT_LIMITS.TRL_MAX),
    pilotFacility: clampStr(input.pilotFacility, BLUEPRINT_LIMITS.ORG_MAX),
    spreadsheetId: clampStr(input.spreadsheetId, BLUEPRINT_LIMITS.ID_MAX * 2),
    spreadsheetTitle: clampStr(input.spreadsheetTitle, BLUEPRINT_LIMITS.SHEET_TITLE_MAX),
    updatedAt: serverTimestamp(),
  };
  try {
    const ref = doc(db, 'pilotConfigs', userId);
    const existing = await getDoc(ref);
    if (existing.exists()) {
      await updateDoc(ref, {
        solverOrg: payload.solverOrg,
        boxSupplier: payload.boxSupplier,
        trlLevel: payload.trlLevel,
        pilotFacility: payload.pilotFacility,
        spreadsheetId: payload.spreadsheetId,
        spreadsheetTitle: payload.spreadsheetTitle,
        updatedAt: serverTimestamp(),
      });
    } else {
      await setDoc(ref, payload);
    }
  } catch (error) {
    handleFirestoreError(error, OperationType.WRITE, path);
  }
}

export async function createPackageWithPackEvent(params: {
  ownerId: string;
  ownerEmail: string;
  code: string;
  fromArea: string;
  targetArea: string;
  zone: string;
  contentSummary: string;
  quantity: number;
  unit: string;
  identificationStatus: IdentificationStatus;
  observations: string;
  operatorName: string;
}): Promise<{ packageId: string; eventId: string }> {
  const packageId = sanitizeId(generatePackageId(), BLUEPRINT_LIMITS.ID_MAX);
  const eventId = sanitizeId(generateEventId('PACK'), BLUEPRINT_LIMITS.EVENT_ID_MAX);
  const logId = sanitizeId(generateEventId('LOG'), BLUEPRINT_LIMITS.EVENT_ID_MAX);
  const nonce = generateNonce();
  const localTimestamp = new Date().toISOString();

  // QR strictly contains only the record reference, zero secrets or full content
  const qrPayload = clampStr(`tai://pkg/${packageId}`, BLUEPRINT_LIMITS.QR_MAX);

  const sealed = await sealEventOnServer({
    packageId,
    eventId,
    eventType: 'pack',
    delivererName: clampStr(params.operatorName, BLUEPRINT_LIMITS.AREA_MAX, 'Operador Embalaje'),
    receiverName: clampStr(params.fromArea, BLUEPRINT_LIMITS.AREA_MAX, 'Área Embalaje'),
    zone: clampStr(params.zone, BLUEPRINT_LIMITS.AREA_MAX, 'Centro Logístico Buenos Aires'),
    functionRole: 'Embalaje y Cierre TAI',
    acceptanceNonce: nonce,
    localTimestamp,
    observations: clampStr(params.observations, BLUEPRINT_LIMITS.OBS_MAX),
  });

  const pkgDoc = {
    id: packageId,
    code: clampStr(params.code, BLUEPRINT_LIMITS.CODE_MAX, packageId),
    ownerId: params.ownerId,
    ownerEmail: clampStr(params.ownerEmail, BLUEPRINT_LIMITS.EMAIL_MAX),
    fromArea: clampStr(params.fromArea, BLUEPRINT_LIMITS.AREA_MAX),
    targetArea: clampStr(params.targetArea, BLUEPRINT_LIMITS.AREA_MAX),
    zone: clampStr(params.zone, BLUEPRINT_LIMITS.AREA_MAX),
    contentSummary: clampStr(params.contentSummary, BLUEPRINT_LIMITS.CONTENT_MAX),
    quantity: Math.max(0, Math.min(1000000, Number(params.quantity) || 0)),
    unit: clampStr(params.unit, BLUEPRINT_LIMITS.UNIT_MAX, 'unidades'),
    identificationStatus: params.identificationStatus,
    sealStatus: 'intact' as SealStatus,
    lifecycleStatus: 'packed' as LifecycleStatus,
    qrPayload,
    observations: clampStr(params.observations, BLUEPRINT_LIMITS.OBS_MAX),
    cvvId: eventId,
    eventCount: 1,
    createdAt: serverTimestamp(),
    updatedAt: serverTimestamp(),
  };

  const evtDoc = {
    id: eventId,
    packageId,
    ownerId: params.ownerId,
    eventType: 'pack' as TraceEventType,
    delivererName: clampStr(params.operatorName, BLUEPRINT_LIMITS.AREA_MAX, 'Operador Embalaje'),
    receiverName: clampStr(params.fromArea, BLUEPRINT_LIMITS.AREA_MAX, 'Estación Embalaje'),
    zone: clampStr(params.zone, BLUEPRINT_LIMITS.AREA_MAX),
    functionRole: 'Embalaje y Cierre TAI',
    observations: clampStr(params.observations, BLUEPRINT_LIMITS.OBS_MAX),
    acceptanceNonce: clampStr(nonce, BLUEPRINT_LIMITS.NONCE_MAX),
    capturedOffline: false,
    offlineSequence: 0,
    localTimestamp: clampStr(localTimestamp, BLUEPRINT_LIMITS.TIMESTAMP_MAX),
    cvvCiphertext: clampStr(sealed.ciphertext, BLUEPRINT_LIMITS.CIPHER_MAX),
    cvvIv: clampStr(sealed.iv, BLUEPRINT_LIMITS.SHORT_HEX_MAX),
    cvvAuthTag: clampStr(sealed.authTag, BLUEPRINT_LIMITS.SHORT_HEX_MAX),
    csgSeal: clampStr(sealed.csgSeal, BLUEPRINT_LIMITS.CSG_MAX),
    cvvState: 'valid',
    discrepancyNote:
      params.identificationStatus === 'uncertain_pending'
        ? 'Material marcado como pendiente/incierto en embalaje; requiere validación.'
        : '',
    createdAt: serverTimestamp(),
  };

  const auditDoc = {
    id: logId,
    ownerId: params.ownerId,
    packageId,
    eventId,
    action: 'cvv_issued' as AuditAction,
    severity: (params.identificationStatus === 'uncertain_pending' ? 'warning' : 'info') as AuditSeverity,
    detail: clampStr(
      `Embalaje TAI registrado (${pkgDoc.code}). Identificación: ${
        params.identificationStatus === 'verified' ? 'Verificada' : 'Pendiente/Incierta'
      }.`,
      BLUEPRINT_LIMITS.OBS_MAX
    ),
    actorEmail: clampStr(params.ownerEmail, BLUEPRINT_LIMITS.EMAIL_MAX),
    createdAt: serverTimestamp(),
  };

  try {
    const batch = writeBatch(db);
    batch.set(doc(db, 'packages', packageId), pkgDoc);
    batch.set(doc(db, `packages/${packageId}/events`, eventId), evtDoc);
    batch.set(doc(db, 'auditLogs', logId), auditDoc);
    await batch.commit();
    return { packageId, eventId };
  } catch (error) {
    handleFirestoreError(error, OperationType.WRITE, `packages/${packageId}`);
  }
}

export async function recordTransferEvent(params: {
  pkg: TaiPackage;
  ownerId: string;
  ownerEmail: string;
  eventType: TraceEventType;
  delivererName: string;
  receiverName: string;
  zone: string;
  functionRole: string;
  observations: string;
  acceptanceNonce: string;
  capturedOffline: boolean;
  offlineSequence: number;
  localTimestamp: string;
  sealStatus: SealStatus;
  discrepancyNote: string;
  nextLifecycleStatus: LifecycleStatus;
}): Promise<{ eventId: string; duplicateOrConflict: boolean; reason?: string }> {
  const eventsCol = collection(db, `packages/${params.pkg.id}/events`);
  const existingEventsSnap = await getDocs(
    query(eventsCol, where('ownerId', '==', params.ownerId))
  ).catch((error) => handleFirestoreError(error, OperationType.LIST, `packages/${params.pkg.id}/events`));

  const existingEvents = existingEventsSnap.docs.map((d) => d.data() as TraceEvent);

  // Rule 1: Duplicate acceptance QR / nonce detection
  const duplicateNonce = existingEvents.find(
    (ev) => ev.acceptanceNonce === params.acceptanceNonce
  );
  if (duplicateNonce) {
    const conflictEventId = sanitizeId(generateEventId('CONF'), BLUEPRINT_LIMITS.EVENT_ID_MAX);
    const logId = sanitizeId(generateEventId('LOG'), BLUEPRINT_LIMITS.EVENT_ID_MAX);
    const reason = `QR de aceptación duplicado (${params.acceptanceNonce}). Rechazado al sincronizar.`;
    const sealed = await sealEventOnServer({
      packageId: params.pkg.id,
      eventId: conflictEventId,
      eventType: 'conflict_detected',
      delivererName: params.delivererName,
      receiverName: params.receiverName,
      zone: params.zone,
      functionRole: params.functionRole,
      acceptanceNonce: `${params.acceptanceNonce}_DUP_${Date.now()}`,
      localTimestamp: params.localTimestamp,
      observations: reason,
    });

    try {
      const batch = writeBatch(db);
      batch.set(doc(db, `packages/${params.pkg.id}/events`, conflictEventId), {
        id: conflictEventId,
        packageId: params.pkg.id,
        ownerId: params.ownerId,
        eventType: 'conflict_detected',
        delivererName: clampStr(params.delivererName, BLUEPRINT_LIMITS.AREA_MAX),
        receiverName: clampStr(params.receiverName, BLUEPRINT_LIMITS.AREA_MAX),
        zone: clampStr(params.zone, BLUEPRINT_LIMITS.AREA_MAX),
        functionRole: clampStr(params.functionRole, BLUEPRINT_LIMITS.AREA_MAX),
        observations: clampStr(params.observations, BLUEPRINT_LIMITS.OBS_MAX),
        acceptanceNonce: clampStr(`${params.acceptanceNonce}_DUP`, BLUEPRINT_LIMITS.NONCE_MAX),
        capturedOffline: params.capturedOffline,
        offlineSequence: params.offlineSequence,
        localTimestamp: clampStr(params.localTimestamp, BLUEPRINT_LIMITS.TIMESTAMP_MAX),
        cvvCiphertext: clampStr(sealed.ciphertext, BLUEPRINT_LIMITS.CIPHER_MAX),
        cvvIv: clampStr(sealed.iv, BLUEPRINT_LIMITS.SHORT_HEX_MAX),
        cvvAuthTag: clampStr(sealed.authTag, BLUEPRINT_LIMITS.SHORT_HEX_MAX),
        csgSeal: clampStr(sealed.csgSeal, BLUEPRINT_LIMITS.CSG_MAX),
        cvvState: 'conflict',
        discrepancyNote: clampStr(reason, BLUEPRINT_LIMITS.DISCREPANCY_MAX),
        createdAt: serverTimestamp(),
      });
      batch.update(doc(db, 'packages', params.pkg.id), {
        lifecycleStatus: 'conflict',
        eventCount: params.pkg.eventCount + 1,
        updatedAt: serverTimestamp(),
      });
      batch.set(doc(db, 'auditLogs', logId), {
        id: logId,
        ownerId: params.ownerId,
        packageId: params.pkg.id,
        eventId: conflictEventId,
        action: 'offline_conflict',
        severity: 'warning',
        detail: clampStr(reason, BLUEPRINT_LIMITS.OBS_MAX),
        actorEmail: clampStr(params.ownerEmail, BLUEPRINT_LIMITS.EMAIL_MAX),
        createdAt: serverTimestamp(),
      });
      await batch.commit();
      return { eventId: conflictEventId, duplicateOrConflict: true, reason };
    } catch (error) {
      handleFirestoreError(error, OperationType.WRITE, `packages/${params.pkg.id}/events`);
    }
  }

  // Rule 2: Incompatible offline sequence detection (e.g., offline event captured with sequence <= existing offline event)
  const hasIncompatibleOffline =
    params.capturedOffline &&
    existingEvents.some(
      (ev) =>
        ev.capturedOffline &&
        ev.offlineSequence >= params.offlineSequence &&
        ev.cvvState === 'valid'
    );

  const eventId = sanitizeId(generateEventId('EVT'), BLUEPRINT_LIMITS.EVENT_ID_MAX);
  const logId = sanitizeId(generateEventId('LOG'), BLUEPRINT_LIMITS.EVENT_ID_MAX);

  const sealed = await sealEventOnServer({
    packageId: params.pkg.id,
    eventId,
    eventType: params.eventType,
    delivererName: params.delivererName,
    receiverName: params.receiverName,
    zone: params.zone,
    functionRole: params.functionRole,
    acceptanceNonce: params.acceptanceNonce,
    localTimestamp: params.localTimestamp,
    observations: params.observations,
  });

  const finalCvvState = hasIncompatibleOffline ? 'conflict' : 'valid';
  const finalLifecycle: LifecycleStatus = hasIncompatibleOffline
    ? 'conflict'
    : params.nextLifecycleStatus;
  const discrepancy = hasIncompatibleOffline
    ? clampStr(
        `Conflicto de secuencia offline (#${params.offlineSequence}). Requiere revisión del supervisor. ${params.discrepancyNote}`,
        BLUEPRINT_LIMITS.DISCREPANCY_MAX
      )
    : clampStr(params.discrepancyNote, BLUEPRINT_LIMITS.DISCREPANCY_MAX);

  try {
    const batch = writeBatch(db);
    batch.set(doc(db, `packages/${params.pkg.id}/events`, eventId), {
      id: eventId,
      packageId: params.pkg.id,
      ownerId: params.ownerId,
      eventType: params.eventType,
      delivererName: clampStr(params.delivererName, BLUEPRINT_LIMITS.AREA_MAX),
      receiverName: clampStr(params.receiverName, BLUEPRINT_LIMITS.AREA_MAX),
      zone: clampStr(params.zone, BLUEPRINT_LIMITS.AREA_MAX),
      functionRole: clampStr(params.functionRole, BLUEPRINT_LIMITS.AREA_MAX),
      observations: clampStr(params.observations, BLUEPRINT_LIMITS.OBS_MAX),
      acceptanceNonce: clampStr(params.acceptanceNonce, BLUEPRINT_LIMITS.NONCE_MAX),
      capturedOffline: params.capturedOffline,
      offlineSequence: params.offlineSequence,
      localTimestamp: clampStr(params.localTimestamp, BLUEPRINT_LIMITS.TIMESTAMP_MAX),
      cvvCiphertext: clampStr(sealed.ciphertext, BLUEPRINT_LIMITS.CIPHER_MAX),
      cvvIv: clampStr(sealed.iv, BLUEPRINT_LIMITS.SHORT_HEX_MAX),
      cvvAuthTag: clampStr(sealed.authTag, BLUEPRINT_LIMITS.SHORT_HEX_MAX),
      csgSeal: clampStr(sealed.csgSeal, BLUEPRINT_LIMITS.CSG_MAX),
      cvvState: finalCvvState,
      discrepancyNote: discrepancy,
      createdAt: serverTimestamp(),
    });

    batch.update(doc(db, 'packages', params.pkg.id), {
      lifecycleStatus: finalLifecycle,
      sealStatus: params.sealStatus,
      targetArea: clampStr(params.receiverName, BLUEPRINT_LIMITS.AREA_MAX),
      zone: clampStr(params.zone, BLUEPRINT_LIMITS.AREA_MAX),
      observations: clampStr(params.observations || params.pkg.observations, BLUEPRINT_LIMITS.OBS_MAX),
      cvvId: eventId,
      eventCount: params.pkg.eventCount + 1,
      updatedAt: serverTimestamp(),
    });

    batch.set(doc(db, 'auditLogs', logId), {
      id: logId,
      ownerId: params.ownerId,
      packageId: params.pkg.id,
      eventId,
      action: hasIncompatibleOffline ? 'offline_conflict' : 'cvv_issued',
      severity: hasIncompatibleOffline ? 'warning' : 'info',
      detail: clampStr(
        hasIncompatibleOffline
          ? `Conflicto offline detectado en ${params.pkg.code} (seq ${params.offlineSequence}).`
          : `CVV emitido (${params.eventType}) para ${params.pkg.code}: ${params.delivererName} → ${params.receiverName}${params.capturedOffline ? ' [Sincronizado Offline]' : ''}.`,
        BLUEPRINT_LIMITS.OBS_MAX
      ),
      actorEmail: clampStr(params.ownerEmail, BLUEPRINT_LIMITS.EMAIL_MAX),
      createdAt: serverTimestamp(),
    });

    await batch.commit();
    return {
      eventId,
      duplicateOrConflict: hasIncompatibleOffline,
      reason: hasIncompatibleOffline ? discrepancy : undefined,
    };
  } catch (error) {
    handleFirestoreError(error, OperationType.WRITE, `packages/${params.pkg.id}`);
  }
}

export async function validateUncertainMaterial(params: {
  pkg: TaiPackage;
  ownerId: string;
  ownerEmail: string;
  confirmedDescription: string;
  confirmedQuantity: number;
  validationNote: string;
}): Promise<void> {
  const logId = sanitizeId(generateEventId('LOG'), BLUEPRINT_LIMITS.EVENT_ID_MAX);
  try {
    const batch = writeBatch(db);
    batch.update(doc(db, 'packages', params.pkg.id), {
      identificationStatus: 'verified',
      contentSummary: clampStr(params.confirmedDescription, BLUEPRINT_LIMITS.CONTENT_MAX),
      quantity: Math.max(0, Number(params.confirmedQuantity) || 0),
      observations: clampStr(params.validationNote, BLUEPRINT_LIMITS.OBS_MAX),
      updatedAt: serverTimestamp(),
    });
    batch.set(doc(db, 'auditLogs', logId), {
      id: logId,
      ownerId: params.ownerId,
      packageId: params.pkg.id,
      eventId: params.pkg.cvvId,
      action: 'material_confirmed',
      severity: 'info',
      detail: clampStr(
        `Material validado para ${params.pkg.code}: ${params.confirmedDescription} (${params.confirmedQuantity} ${params.pkg.unit}).`,
        BLUEPRINT_LIMITS.OBS_MAX
      ),
      actorEmail: clampStr(params.ownerEmail, BLUEPRINT_LIMITS.EMAIL_MAX),
      createdAt: serverTimestamp(),
    });
    await batch.commit();
  } catch (error) {
    handleFirestoreError(error, OperationType.UPDATE, `packages/${params.pkg.id}`);
  }
}

export async function invalidateCvvByCsg(params: {
  pkg: TaiPackage;
  event: TraceEvent;
  ownerId: string;
  ownerEmail: string;
  reason: string;
}): Promise<void> {
  const logId = sanitizeId(generateEventId('CSG'), BLUEPRINT_LIMITS.EVENT_ID_MAX);
  try {
    const batch = writeBatch(db);
    batch.update(doc(db, `packages/${params.pkg.id}/events`, params.event.id), {
      cvvState: 'invalidated_csg',
      discrepancyNote: clampStr(params.reason, BLUEPRINT_LIMITS.DISCREPANCY_MAX),
    });
    batch.set(doc(db, 'auditLogs', logId), {
      id: logId,
      ownerId: params.ownerId,
      packageId: params.pkg.id,
      eventId: params.event.id,
      action: 'csg_tamper_invalidated',
      severity: 'critical',
      detail: clampStr(
        `CSG invalidó CVV ${params.event.id} (${params.pkg.code}): ${params.reason} Registro maestro conservado en auditoría.`,
        BLUEPRINT_LIMITS.OBS_MAX
      ),
      actorEmail: clampStr(params.ownerEmail, BLUEPRINT_LIMITS.EMAIL_MAX),
      createdAt: serverTimestamp(),
    });
    await batch.commit();
  } catch (error) {
    handleFirestoreError(error, OperationType.WRITE, `packages/${params.pkg.id}/events/${params.event.id}`);
  }
}

export async function logSheetsSyncAudit(params: {
  ownerId: string;
  ownerEmail: string;
  packageId: string;
  detail: string;
}): Promise<void> {
  const logId = sanitizeId(generateEventId('SHT'), BLUEPRINT_LIMITS.EVENT_ID_MAX);
  try {
    await setDoc(doc(db, 'auditLogs', logId), {
      id: logId,
      ownerId: params.ownerId,
      packageId: sanitizeId(params.packageId, BLUEPRINT_LIMITS.ID_MAX),
      eventId: '',
      action: 'sheets_synced',
      severity: 'info',
      detail: clampStr(params.detail, BLUEPRINT_LIMITS.OBS_MAX),
      actorEmail: clampStr(params.ownerEmail, BLUEPRINT_LIMITS.EMAIL_MAX),
      createdAt: serverTimestamp(),
    });
  } catch (error) {
    handleFirestoreError(error, OperationType.CREATE, `auditLogs/${logId}`);
  }
}

export async function loadPilotBaselineScenario(ownerId: string, ownerEmail: string): Promise<void> {
  const p1 = await createPackageWithPackEvent({
    ownerId,
    ownerEmail,
    code: 'TAI-BA-1042',
    fromArea: 'Almacén Central Dock Sud',
    targetArea: 'Módulo Mantenimiento Compresores',
    zone: 'Zona Operativa Sur · Dock Sud',
    contentSummary: 'Válvulas de alivio PN40 certificadas + kit de juntas',
    quantity: 12,
    unit: 'piezas',
    identificationStatus: 'verified',
    observations: 'Cierre TAI adherido sobre solapa diagonal superior. Etiquetas legibles.',
    operatorName: 'M. Fernández (Embalaje)',
  });

  const p2 = await createPackageWithPackEvent({
    ownerId,
    ownerEmail,
    code: 'TAI-BA-1043',
    fromArea: 'Recepción Proveedores Avellaneda',
    targetArea: 'Laboratorio Inspección Materiales',
    zone: 'Nave B · Clasificación',
    contentSummary: 'Lote repuestos eléctricos sin código SAP legible (pendiente catalogación)',
    quantity: 4,
    unit: 'cajas internas',
    identificationStatus: 'uncertain_pending',
    observations: 'Marcado como pendiente/incierto hasta validación técnica según procedimiento YPF.',
    operatorName: 'L. Gómez (Recepción)',
  });

  // Add a real receive event on p1
  const snap = await getDoc(doc(db, 'packages', p1.packageId));
  if (snap.exists()) {
    const pkg1 = snap.data() as TaiPackage;
    await recordTransferEvent({
      pkg: pkg1,
      ownerId,
      ownerEmail,
      eventType: 'receive',
      delivererName: 'Transporte Interno BA-04',
      receiverName: 'Módulo Mantenimiento Compresores',
      zone: 'Módulo Mantenimiento Compresores',
      functionRole: 'Supervisor de Recepción',
      observations: 'Cierre TAI intacto. QR verificado en dispositivo móvil.',
      acceptanceNonce: generateNonce(),
      capturedOffline: false,
      offlineSequence: 0,
      localTimestamp: new Date().toISOString(),
      sealStatus: 'intact',
      discrepancyNote: '',
      nextLifecycleStatus: 'received',
    });
  }

  // Keep p2 ready for material validation
  void p2;
}

export function buildOfflineQueueStorageKey(userId: string): string {
  return `tai_offline_queue_${userId}`;
}

export function readOfflineQueue(userId: string): OfflinePendingEvent[] {
  try {
    const raw = window.localStorage.getItem(buildOfflineQueueStorageKey(userId));
    if (!raw) return [];
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? (parsed as OfflinePendingEvent[]) : [];
  } catch {
    return [];
  }
}

export function writeOfflineQueue(userId: string, queue: OfflinePendingEvent[]): void {
  window.localStorage.setItem(buildOfflineQueueStorageKey(userId), JSON.stringify(queue));
}
