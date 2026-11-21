export type IdentificationStatus = 'verified' | 'uncertain_pending';
export type SealStatus = 'intact' | 'opened' | 'damaged';
export type LifecycleStatus =
  | 'packed'
  | 'in_transit'
  | 'received'
  | 'return_open'
  | 'conflict'
  | 'audited';

export type TraceEventType =
  | 'pack'
  | 'dispatch'
  | 'receive'
  | 'return'
  | 'material_validation'
  | 'csg_invalidation'
  | 'conflict_detected';

export type CvvState = 'valid' | 'invalidated_csg' | 'conflict';

export type AuditAction =
  | 'cvv_issued'
  | 'cvv_verified'
  | 'csg_tamper_invalidated'
  | 'offline_conflict'
  | 'sheets_synced'
  | 'material_confirmed';

export type AuditSeverity = 'info' | 'warning' | 'critical';

export const BLUEPRINT_LIMITS = {
  ID_MAX: 64,
  EVENT_ID_MAX: 128,
  CODE_MAX: 64,
  EMAIL_MAX: 160,
  AREA_MAX: 120,
  CONTENT_MAX: 300,
  UNIT_MAX: 40,
  QR_MAX: 200,
  OBS_MAX: 500,
  NONCE_MAX: 128,
  TIMESTAMP_MAX: 64,
  CIPHER_MAX: 2000,
  SHORT_HEX_MAX: 64,
  CSG_MAX: 128,
  DISCREPANCY_MAX: 400,
  ORG_MAX: 160,
  TRL_MAX: 64,
  SHEET_TITLE_MAX: 200,
  HASH_MAX: 128,
  CRYPTO_ID_MAX: 160,
  KEY_ID_MAX: 64,
  SIG_MAX: 256,
  ID_PATTERN: /^[a-zA-Z0-9_-]+$/,
} as const;

export interface TaiPackage {
  id: string;
  code: string;
  ownerId: string;
  ownerEmail: string;
  fromArea: string;
  targetArea: string;
  zone: string;
  contentSummary: string;
  quantity: number;
  unit: string;
  identificationStatus: IdentificationStatus;
  sealStatus: SealStatus;
  lifecycleStatus: LifecycleStatus;
  qrPayload: string;
  observations: string;
  cvvId: string;
  eventCount: number;
  createdAt?: unknown;
  updatedAt?: unknown;
}

export interface TraceEvent {
  id: string;
  packageId: string;
  ownerId: string;
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
  cvvCiphertext: string;
  cvvIv: string;
  cvvAuthTag: string;
  csgSeal: string;
  cvvState: CvvState;
  discrepancyNote: string;
  acceptanceHash?: string;
  acceptanceCryptoId?: string;
  receiverUid?: string;
  receiverKeyId?: string;
  receiverSignature?: string;
  createdAt?: unknown;
}

export interface AuditLog {
  id: string;
  ownerId: string;
  packageId: string;
  eventId: string;
  action: AuditAction;
  severity: AuditSeverity;
  detail: string;
  actorEmail: string;
  createdAt?: unknown;
}

export interface PilotConfig {
  ownerId: string;
  solverOrg: string;
  boxSupplier: string;
  trlLevel: string;
  pilotFacility: string;
  spreadsheetId: string;
  spreadsheetTitle: string;
  updatedAt?: unknown;
}

export interface AcceptanceProof {
  version: 'TAI-ACCEPT-V2';
  receiverUid: string;
  receiverDeviceId: string;
  receiverKeyId: string;
  receiverPublicKeyB64u: string;
  issuedAt: string;
  acceptanceHash: string;
  acceptanceCryptoId: string;
  signatureB64u: string;
}

export interface StationCertificate {
  version: 'TAI-STATION-CERT-V1';
  stationKeyId: string;
  stationPublicKeyB64u: string;
  deviceId: string;
  operatorUid: string;
  operatorEmail: string;
  issuedAt: string;
  expiresAt: string;
  issuerKeyId: string;
  issuerPublicKeyB64u: string;
  issuerSignatureB64u: string;
}

export interface CrossStationEventProof {
  version: 'TAI-EVENT-PROOF-V1';
  csgProviderId: 'webcrypto-ecdsa-p256-hmac-v1' | 'csg-rust-sello-integridad-wasm';
  stationKeyId: string;
  stationPublicKeyB64u: string;
  stationSignatureB64u: string;
  stationCert?: StationCertificate;
  acceptanceProof?: AcceptanceProof;
  deviceId?: string;
  operatorUid?: string;
  operatorEmail?: string;
}

export interface OfflinePendingEvent {
  localId: string;
  eventId: string;
  packageId: string;
  packageCode: string;
  eventType: TraceEventType;
  delivererName: string;
  receiverName: string;
  zone: string;
  functionRole: string;
  observations: string;
  acceptanceNonce: string;
  offlineSequence: number;
  deviceId: string;
  localTimestamp: string;
  sealStatus: SealStatus;
  discrepancyNote: string;
  cvvCiphertext: string;
  cvvIv: string;
  cvvAuthTag: string;
  csgSeal: string;
  acceptanceHash?: string;
  acceptanceCryptoId?: string;
  receiverUid?: string;
  receiverKeyId?: string;
  receiverSignature?: string;
  proof?: CrossStationEventProof;
  retryCount?: number;
  lastSyncError?: string;
}

export interface GroundedPlace {
  title: string;
  uri: string;
  placeId?: string;
  reviewSnippets?: Array<{
    uri?: string;
    title?: string;
    authorAttribution?: { displayName?: string };
  }>;
}
