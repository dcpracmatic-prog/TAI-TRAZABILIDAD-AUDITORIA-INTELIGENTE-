import type {
  AcceptanceProof,
  CrossStationEventProof,
  OfflinePendingEvent,
  StationCertificate,
  TraceEventType,
} from '../types/tai';

export const OFFLINE_CRYPTO_CONFIG = {
  vaultVersion: 'TAI-OFFLINE-VAULT-V1',
  cvvPayloadVersion: 'TAI-CVV-OFFLINE-HTML-1',
  acceptQrVersion: 'TAI-ACCEPT-V2',
  stationCertVersion: 'TAI-STATION-CERT-V1',
  eventProofVersion: 'TAI-EVENT-PROOF-V1',
  algorithmLabel: 'PBKDF2-SHA256 + AES-256-GCM + ECDSA-P256 + HMAC-SHA256',
  pbkdf2Iterations: 310000,
  aesKeyLengthBits: 256,
  aesGcmIvBytes: 12,
  aesGcmTagLengthBits: 128,
  vaultTtlMs: 7 * 24 * 60 * 60 * 1000,
  acceptanceMaxAgeMs: 24 * 60 * 60 * 1000,
} as const;

export interface CsgSealProvider {
  readonly providerId: 'webcrypto-ecdsa-p256-hmac-v1' | 'csg-rust-sello-integridad-wasm';
  readonly displayName: string;
  readonly usesRustSelloIntegridad: boolean;
}

export const ACTIVE_CSG_PROVIDER: CsgSealProvider = {
  providerId: 'webcrypto-ecdsa-p256-hmac-v1',
  displayName:
    'Sello piloto Web Crypto (ECDSA P-256 + HMAC-SHA256 + AES-256-GCM; adaptador preparado para crate Rust sello_integridad, aún no enlazado)',
  usesRustSelloIntegridad: false,
};

export interface OfflineSessionKeys {
  aesKey: CryptoKey;
  hmacKey: CryptoKey;
}

export interface EcdsaSigningIdentity {
  privateKey: CryptoKey;
  publicKey: CryptoKey;
  publicKeyB64u: string;
  keyId: string;
}

export interface OfflineOperatorIdentity {
  uid: string;
  email: string;
  displayName: string;
  role?: string;
}

export interface OfflineVaultEnvelope {
  version: string;
  algorithm: string;
  iterations: number;
  saltHex: string;
  ivHex: string;
  ciphertextHex: string;
  expiresAt: string;
  stationKeyId?: string;
  stationCert?: StationCertificate;
}

export interface UnlockedOfflineSession {
  operator: Required<OfflineOperatorIdentity>;
  deviceId: string;
  issuedAt: string;
  expiresAt: string;
  keys: OfflineSessionKeys;
  ecdsa: {
    privateKey: CryptoKey;
    publicKeyB64u: string;
    keyId: string;
    stationCert?: StationCertificate;
  };
}

export interface OfflineTransferSealInput {
  packageId: string;
  eventId?: string;
  eventType: TraceEventType;
  delivererName: string;
  receiverName: string;
  zone: string;
  functionRole: string;
  acceptanceNonce: string;
  localTimestamp: string;
  observations: string;
  capturedOffline?: boolean;
  deviceId: string;
  operatorUid?: string;
  operatorEmail?: string;
  acceptanceProof?: AcceptanceProof;
}

export interface OfflineTransferSealOutput {
  eventId: string;
  ciphertext: string;
  iv: string;
  authTag: string;
  csgSeal: string;
  algorithm: string;
}

export interface OfflineCsgVerifyResult {
  valid: boolean;
  csgStatus: 'VERIFIED' | 'INVALIDATED_TAMPERED' | 'OUT_OF_FLOW';
  reason: string;
  decryptedPayload?: Record<string, unknown>;
}

export interface ParsedAcceptanceQr {
  packageId: string;
  eventType: 'dispatch' | 'receive' | 'return';
  nonce: string;
  acceptanceHash: string;
  acceptanceCryptoId: string;
  receiverName: string;
  zone: string;
  receiverUid: string;
  receiverDeviceId: string;
  issuedAt: string;
  proof: AcceptanceProof;
}

function getSubtleCrypto(): SubtleCrypto {
  if (typeof globalThis.crypto === 'undefined' || !globalThis.crypto.subtle) {
    throw new Error('Web Crypto API no está disponible en este entorno.');
  }
  return globalThis.crypto.subtle;
}

function cleanQrSegment(value: string, maxLen = 120): string {
  return String(value || '')
    .replace(/\|/g, '/')
    .replace(/[\r\n]/g, ' ')
    .trim()
    .slice(0, maxLen);
}

export function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

export function hexToBytes(hex: string): Uint8Array {
  const clean = String(hex || '').trim();
  if (clean.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(clean)) {
    throw new Error('Cadena hexadecimal inválida.');
  }
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

export function base64UrlEncode(bytes: Uint8Array): string {
  let binary = '';
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

export function base64UrlDecode(str: string): Uint8Array {
  const clean = String(str || '')
    .trim()
    .replace(/-/g, '+')
    .replace(/_/g, '/');
  const pad = clean.length % 4 === 0 ? '' : '='.repeat(4 - (clean.length % 4));
  const binary = atob(clean + pad);
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    out[i] = binary.charCodeAt(i);
  }
  return out;
}

export async function computeKeyThumbprint(spkiBytes: Uint8Array): Promise<string> {
  const subtle = getSubtleCrypto();
  const digest = await subtle.digest('SHA-256', spkiBytes as BufferSource);
  return bytesToHex(new Uint8Array(digest)).slice(0, 16).toUpperCase();
}

export async function generateEcdsaIdentityKeyPair(
  extractable = false
): Promise<EcdsaSigningIdentity> {
  const subtle = getSubtleCrypto();
  const pair = await subtle.generateKey(
    { name: 'ECDSA', namedCurve: 'P-256' },
    extractable,
    ['sign', 'verify']
  );
  const spki = new Uint8Array(await subtle.exportKey('spki', pair.publicKey));
  const publicKeyB64u = base64UrlEncode(spki);
  const keyId = await computeKeyThumbprint(spki);
  return {
    privateKey: pair.privateKey,
    publicKey: pair.publicKey,
    publicKeyB64u,
    keyId,
  };
}

export async function importEcdsaPublicKey(
  publicKeyB64u: string
): Promise<{ publicKey: CryptoKey; keyId: string }> {
  const subtle = getSubtleCrypto();
  const spki = base64UrlDecode(publicKeyB64u);
  const publicKey = await subtle.importKey(
    'spki',
    spki as BufferSource,
    { name: 'ECDSA', namedCurve: 'P-256' },
    true,
    ['verify']
  );
  const keyId = await computeKeyThumbprint(spki);
  return { publicKey, keyId };
}

export function generateOfflineNonce(): string {
  const rnd = globalThis.crypto.getRandomValues(new Uint8Array(4));
  return `ACC_${Date.now().toString(36).toUpperCase()}_${bytesToHex(rnd).toUpperCase()}`;
}

export function generateOfflineEventId(prefix = 'CVV_OFF'): string {
  const rnd = globalThis.crypto.getRandomValues(new Uint8Array(4));
  const cleanPrefix = prefix.replace(/[^a-zA-Z0-9_]/g, '').slice(0, 12) || 'CVV_OFF';
  return `${cleanPrefix}_${Date.now().toString(36).toUpperCase()}_${bytesToHex(rnd).toUpperCase()}`;
}

export async function generateOfflineSessionKeys(extractable = false): Promise<OfflineSessionKeys> {
  const subtle = getSubtleCrypto();
  const [aesKey, hmacKey] = await Promise.all([
    subtle.generateKey(
      { name: 'AES-GCM', length: OFFLINE_CRYPTO_CONFIG.aesKeyLengthBits },
      extractable,
      ['encrypt', 'decrypt']
    ),
    subtle.generateKey(
      { name: 'HMAC', hash: 'SHA-256', length: 256 },
      extractable,
      ['sign', 'verify']
    ),
  ]);
  return { aesKey, hmacKey };
}

export async function exportOfflineSessionKeysJwk(
  keys: OfflineSessionKeys
): Promise<{ aesJwk: JsonWebKey; hmacJwk: JsonWebKey }> {
  const subtle = getSubtleCrypto();
  const [aesJwk, hmacJwk] = await Promise.all([
    subtle.exportKey('jwk', keys.aesKey),
    subtle.exportKey('jwk', keys.hmacKey),
  ]);
  return { aesJwk, hmacJwk };
}

export async function importOfflineSessionKeysJwk(
  aesJwk: JsonWebKey,
  hmacJwk: JsonWebKey,
  extractable = false
): Promise<OfflineSessionKeys> {
  const subtle = getSubtleCrypto();
  const [aesKey, hmacKey] = await Promise.all([
    subtle.importKey(
      'jwk',
      aesJwk,
      { name: 'AES-GCM', length: OFFLINE_CRYPTO_CONFIG.aesKeyLengthBits },
      extractable,
      ['encrypt', 'decrypt']
    ),
    subtle.importKey(
      'jwk',
      hmacJwk,
      { name: 'HMAC', hash: 'SHA-256' },
      extractable,
      ['sign', 'verify']
    ),
  ]);
  return { aesKey, hmacKey };
}

export async function computeReceiverAcceptanceHash(params: {
  packageId: string;
  eventType: string;
  nonce: string;
  receiverUid: string;
  receiverDeviceId: string;
  receiverKeyId: string;
  issuedAt: string;
}): Promise<string> {
  const canonical = [
    'TAI-ACCEPT-ID-V1',
    params.packageId,
    params.eventType,
    params.nonce,
    params.receiverUid,
    params.receiverDeviceId,
    params.receiverKeyId,
    params.issuedAt,
  ].join('|');
  const digest = await getSubtleCrypto().digest('SHA-256', new TextEncoder().encode(canonical));
  return bytesToHex(new Uint8Array(digest));
}

export function formatAcceptanceCryptoId(nonce: string, acceptanceHash: string): string {
  return `${nonce}:${acceptanceHash.slice(0, 16).toUpperCase()}`;
}

export function buildAcceptanceCanonicalString(params: {
  packageId: string;
  eventType: string;
  nonce: string;
  receiverName: string;
  zone: string;
  receiverUid: string;
  receiverDeviceId: string;
  issuedAt: string;
  acceptanceHash: string;
}): string {
  return [
    OFFLINE_CRYPTO_CONFIG.acceptQrVersion,
    params.packageId,
    params.eventType,
    params.nonce,
    params.receiverName,
    params.zone,
    params.receiverUid,
    params.receiverDeviceId,
    params.issuedAt,
    params.acceptanceHash,
  ].join('|');
}

export async function signAcceptanceQrPayload(
  params: {
    packageId: string;
    eventType: 'dispatch' | 'receive' | 'return';
    nonce: string;
    receiverName: string;
    zone: string;
    receiverUid: string;
    receiverDeviceId: string;
    issuedAt?: string;
  },
  signer: { privateKey: CryptoKey; publicKeyB64u: string; keyId: string }
): Promise<{
  qrString: string;
  acceptanceHash: string;
  acceptanceCryptoId: string;
  proof: AcceptanceProof;
}> {
  const subtle = getSubtleCrypto();
  const issuedAt = params.issuedAt || new Date().toISOString();
  const packageId = cleanQrSegment(params.packageId, 64);
  const nonce = cleanQrSegment(params.nonce, 128);
  const receiverName = cleanQrSegment(params.receiverName || 'Receptor en sitio', 120);
  const zone = cleanQrSegment(params.zone || 'Centro Logístico Buenos Aires', 120);
  const receiverUid = cleanQrSegment(params.receiverUid || 'LOCAL_OPERATOR', 128);
  const receiverDeviceId = cleanQrSegment(params.receiverDeviceId || 'DISP_LOCAL', 64);

  const acceptanceHash = await computeReceiverAcceptanceHash({
    packageId,
    eventType: params.eventType,
    nonce,
    receiverUid,
    receiverDeviceId,
    receiverKeyId: signer.keyId,
    issuedAt,
  });
  const acceptanceCryptoId = formatAcceptanceCryptoId(nonce, acceptanceHash);

  const canonical = buildAcceptanceCanonicalString({
    packageId,
    eventType: params.eventType,
    nonce,
    receiverName,
    zone,
    receiverUid,
    receiverDeviceId,
    issuedAt,
    acceptanceHash,
  });

  const sigBuf = await subtle.sign(
    { name: 'ECDSA', hash: 'SHA-256' },
    signer.privateKey,
    new TextEncoder().encode(canonical)
  );
  const signatureB64u = base64UrlEncode(new Uint8Array(sigBuf));

  const qrString = [
    'tai://accept',
    packageId,
    params.eventType,
    nonce,
    receiverName,
    zone,
    receiverUid,
    receiverDeviceId,
    issuedAt,
    signer.keyId,
    signatureB64u,
    signer.publicKeyB64u,
    acceptanceHash,
  ].join('|');

  return {
    qrString,
    acceptanceHash,
    acceptanceCryptoId,
    proof: {
      version: OFFLINE_CRYPTO_CONFIG.acceptQrVersion,
      receiverUid,
      receiverDeviceId,
      receiverKeyId: signer.keyId,
      receiverPublicKeyB64u: signer.publicKeyB64u,
      issuedAt,
      acceptanceHash,
      acceptanceCryptoId,
      signatureB64u,
    },
  };
}

export async function parseAndVerifyAcceptanceQr(
  raw: string,
  options?: { maxAgeMs?: number; nowMs?: number }
): Promise<{
  valid: boolean;
  parsed?: ParsedAcceptanceQr;
  reason: string;
}> {
  const trimmed = String(raw || '').trim();
  if (!trimmed.startsWith('tai://accept|')) {
    return {
      valid: false,
      reason: 'El código escaneado no corresponde a un QR de aceptación TAI válido (tai://accept|...).',
    };
  }

  const parts = trimmed.split('|');
  if (parts.length < 13) {
    return {
      valid: false,
      reason:
        'El QR de aceptación no contiene el identificador criptográfico (nonce + hash) y la firma ECDSA P-256 del receptor. Solicita al receptor generar un QR actualizado.',
    };
  }

  const packageId = (parts[1] || '').trim();
  const evt = (parts[2] || '').trim();
  const nonce = (parts[3] || '').trim();
  const receiverName = (parts[4] || '').trim() || 'Receptor en sitio';
  const zone = (parts[5] || '').trim() || 'Centro Logístico Buenos Aires';
  const receiverUid = (parts[6] || '').trim();
  const receiverDeviceId = (parts[7] || '').trim();
  const issuedAt = (parts[8] || '').trim();
  const keyId = (parts[9] || '').trim();
  const signatureB64u = (parts[10] || '').trim();
  const publicKeyB64u = (parts[11] || '').trim();
  const acceptanceHash = (parts[12] || '').trim().toLowerCase();

  if (
    !packageId ||
    (evt !== 'dispatch' && evt !== 'receive' && evt !== 'return') ||
    nonce.length < 4 ||
    !receiverUid ||
    !receiverDeviceId ||
    !issuedAt ||
    !keyId ||
    !signatureB64u ||
    !publicKeyB64u ||
    !/^[0-9a-f]{64}$/.test(acceptanceHash)
  ) {
    return {
      valid: false,
      reason: 'El QR de aceptación firmado tiene campos obligatorios o hash SHA-256 inválidos.',
    };
  }

  const issuedMs = Date.parse(issuedAt);
  const nowMs = options?.nowMs ?? Date.now();
  const maxAgeMs = options?.maxAgeMs ?? OFFLINE_CRYPTO_CONFIG.acceptanceMaxAgeMs;
  if (!Number.isFinite(issuedMs)) {
    return { valid: false, reason: 'Marca de tiempo inválida en el QR de aceptación.' };
  }
  if (issuedMs > nowMs + 5 * 60 * 1000) {
    return { valid: false, reason: 'El QR de aceptación tiene fecha futura fuera de tolerancia.' };
  }
  if (nowMs - issuedMs > maxAgeMs) {
    return { valid: false, reason: 'El QR de aceptación expiró. Solicita un QR nuevo al receptor.' };
  }

  try {
    const { publicKey, keyId: computedKeyId } = await importEcdsaPublicKey(publicKeyB64u);
    if (computedKeyId !== keyId) {
      return {
        valid: false,
        reason: 'La huella criptográfica (kid) de la clave del receptor no coincide con la clave pública del QR.',
      };
    }

    const expectedHash = await computeReceiverAcceptanceHash({
      packageId,
      eventType: evt,
      nonce,
      receiverUid,
      receiverDeviceId,
      receiverKeyId: keyId,
      issuedAt,
    });
    if (expectedHash !== acceptanceHash) {
      return {
        valid: false,
        reason:
          'El identificador criptográfico (nonce + hash) no coincide con la identidad declarada del receptor.',
      };
    }

    const acceptanceCryptoId = formatAcceptanceCryptoId(nonce, acceptanceHash);

    const canonical = buildAcceptanceCanonicalString({
      packageId,
      eventType: evt,
      nonce,
      receiverName,
      zone,
      receiverUid,
      receiverDeviceId,
      issuedAt,
      acceptanceHash,
    });

    const sigBytes = base64UrlDecode(signatureB64u);
    const sigOk = await getSubtleCrypto().verify(
      { name: 'ECDSA', hash: 'SHA-256' },
      publicKey,
      sigBytes as BufferSource,
      new TextEncoder().encode(canonical)
    );

    if (!sigOk) {
      return {
        valid: false,
        reason:
          'Firma del receptor inválida o QR alterado (ECDSA P-256). No se puede confirmar quién aceptó.',
      };
    }

    const proof: AcceptanceProof = {
      version: OFFLINE_CRYPTO_CONFIG.acceptQrVersion,
      receiverUid,
      receiverDeviceId,
      receiverKeyId: keyId,
      receiverPublicKeyB64u: publicKeyB64u,
      issuedAt,
      acceptanceHash,
      acceptanceCryptoId,
      signatureB64u,
    };

    return {
      valid: true,
      parsed: {
        packageId,
        eventType: evt,
        nonce,
        acceptanceHash,
        acceptanceCryptoId,
        receiverName,
        zone,
        receiverUid,
        receiverDeviceId,
        issuedAt,
        proof,
      },
      reason: `Receptor verificado (${receiverUid} · ${acceptanceCryptoId} · clave #${keyId}).`,
    };
  } catch {
    return {
      valid: false,
      reason: 'No se pudo verificar la firma criptográfica del receptor en el QR.',
    };
  }
}

export function buildStationCertCanonical(cert: Omit<StationCertificate, 'issuerSignatureB64u'>): string {
  return [
    cert.version,
    cert.stationKeyId,
    cert.stationPublicKeyB64u,
    cert.deviceId,
    cert.operatorUid,
    cert.operatorEmail,
    cert.issuedAt,
    cert.expiresAt,
    cert.issuerKeyId,
  ].join('|');
}

export async function issueStationCertificate(
  params: {
    stationKeyId: string;
    stationPublicKeyB64u: string;
    deviceId: string;
    operatorUid: string;
    operatorEmail: string;
    issuedAt: string;
    expiresAt: string;
  },
  issuer: { privateKey: CryptoKey; publicKeyB64u: string; keyId: string }
): Promise<StationCertificate> {
  const baseCert: Omit<StationCertificate, 'issuerSignatureB64u'> = {
    version: OFFLINE_CRYPTO_CONFIG.stationCertVersion,
    stationKeyId: params.stationKeyId,
    stationPublicKeyB64u: params.stationPublicKeyB64u,
    deviceId: params.deviceId,
    operatorUid: params.operatorUid,
    operatorEmail: params.operatorEmail,
    issuedAt: params.issuedAt,
    expiresAt: params.expiresAt,
    issuerKeyId: issuer.keyId,
    issuerPublicKeyB64u: issuer.publicKeyB64u,
  };
  const canonical = buildStationCertCanonical(baseCert);
  const sigBuf = await getSubtleCrypto().sign(
    { name: 'ECDSA', hash: 'SHA-256' },
    issuer.privateKey,
    new TextEncoder().encode(canonical)
  );
  return {
    ...baseCert,
    issuerSignatureB64u: base64UrlEncode(new Uint8Array(sigBuf)),
  };
}

export async function verifyStationCertificate(
  cert: StationCertificate,
  options?: { trustedIssuerKeyIds?: string[]; referenceTimeMs?: number }
): Promise<{ valid: boolean; reason: string }> {
  try {
    if (!cert || cert.version !== OFFLINE_CRYPTO_CONFIG.stationCertVersion) {
      return { valid: false, reason: 'Certificado de estación inválido.' };
    }
    const { keyId: computedStationKeyId } = await importEcdsaPublicKey(cert.stationPublicKeyB64u);
    if (computedStationKeyId !== cert.stationKeyId) {
      return { valid: false, reason: 'La clave pública de la estación no coincide con stationKeyId.' };
    }

    const { publicKey: issuerPub, keyId: computedIssuerKeyId } = await importEcdsaPublicKey(
      cert.issuerPublicKeyB64u
    );
    if (computedIssuerKeyId !== cert.issuerKeyId) {
      return { valid: false, reason: 'La huella del emisor del certificado de estación no coincide.' };
    }

    if (
      options?.trustedIssuerKeyIds &&
      options.trustedIssuerKeyIds.length > 0 &&
      !options.trustedIssuerKeyIds.includes(cert.issuerKeyId)
    ) {
      return {
        valid: false,
        reason: `El certificado de estación fue emitido por una clave desconocida (#${cert.issuerKeyId}).`,
      };
    }

    const refMs = options?.referenceTimeMs ?? Date.now();
    const expMs = Date.parse(cert.expiresAt);
    if (!Number.isFinite(expMs) || refMs > expMs) {
      return { valid: false, reason: 'El certificado de la estación offline expiró.' };
    }

    const canonical = buildStationCertCanonical({
      version: cert.version,
      stationKeyId: cert.stationKeyId,
      stationPublicKeyB64u: cert.stationPublicKeyB64u,
      deviceId: cert.deviceId,
      operatorUid: cert.operatorUid,
      operatorEmail: cert.operatorEmail,
      issuedAt: cert.issuedAt,
      expiresAt: cert.expiresAt,
      issuerKeyId: cert.issuerKeyId,
      issuerPublicKeyB64u: cert.issuerPublicKeyB64u,
    });

    const sigOk = await getSubtleCrypto().verify(
      { name: 'ECDSA', hash: 'SHA-256' },
      issuerPub,
      base64UrlDecode(cert.issuerSignatureB64u) as BufferSource,
      new TextEncoder().encode(canonical)
    );
    if (!sigOk) {
      return { valid: false, reason: 'Firma del emisor del certificado de estación inválida.' };
    }

    return {
      valid: true,
      reason: `Certificado de estación #${cert.stationKeyId} válido (emitido por #${cert.issuerKeyId}).`,
    };
  } catch {
    return { valid: false, reason: 'Error verificando el certificado criptográfico de la estación.' };
  }
}

export function buildCrossStationEventCanonical(params: {
  packageId: string;
  eventId: string;
  eventType: string;
  acceptanceNonce: string;
  acceptanceSigB64u: string;
  cvvCiphertext: string;
  cvvIv: string;
  cvvAuthTag: string;
  localTimestamp: string;
  deviceId: string;
  operatorUid: string;
}): string {
  return [
    OFFLINE_CRYPTO_CONFIG.eventProofVersion,
    params.packageId,
    params.eventId,
    params.eventType,
    params.acceptanceNonce,
    params.acceptanceSigB64u,
    params.cvvCiphertext,
    params.cvvIv,
    params.cvvAuthTag,
    params.localTimestamp,
    params.deviceId,
    params.operatorUid,
  ].join('|');
}

export async function signCrossStationEvent(
  params: {
    packageId: string;
    eventId: string;
    eventType: string;
    acceptanceNonce: string;
    cvvCiphertext: string;
    cvvIv: string;
    cvvAuthTag: string;
    localTimestamp: string;
    deviceId: string;
    operatorUid?: string;
    operatorEmail?: string;
    acceptanceProof?: AcceptanceProof;
    stationCert?: StationCertificate;
  },
  stationSigner: { privateKey: CryptoKey; publicKeyB64u: string; keyId: string }
): Promise<CrossStationEventProof> {
  const operatorUid = params.operatorUid || params.stationCert?.operatorUid || 'LOCAL_OPERATOR';
  const operatorEmail = params.operatorEmail || params.stationCert?.operatorEmail || '';
  const canonical = buildCrossStationEventCanonical({
    packageId: params.packageId,
    eventId: params.eventId,
    eventType: params.eventType,
    acceptanceNonce: params.acceptanceNonce,
    acceptanceSigB64u: params.acceptanceProof?.signatureB64u || 'NO_ACCEPTANCE_SIG',
    cvvCiphertext: params.cvvCiphertext,
    cvvIv: params.cvvIv,
    cvvAuthTag: params.cvvAuthTag,
    localTimestamp: params.localTimestamp,
    deviceId: params.deviceId,
    operatorUid,
  });

  const sigBuf = await getSubtleCrypto().sign(
    { name: 'ECDSA', hash: 'SHA-256' },
    stationSigner.privateKey,
    new TextEncoder().encode(canonical)
  );

  return {
    version: OFFLINE_CRYPTO_CONFIG.eventProofVersion,
    csgProviderId: ACTIVE_CSG_PROVIDER.providerId,
    stationKeyId: stationSigner.keyId,
    stationPublicKeyB64u: stationSigner.publicKeyB64u,
    stationSignatureB64u: base64UrlEncode(new Uint8Array(sigBuf)),
    ...(params.stationCert ? { stationCert: params.stationCert } : {}),
    ...(params.acceptanceProof ? { acceptanceProof: params.acceptanceProof } : {}),
    deviceId: params.deviceId,
    operatorUid,
    operatorEmail,
  };
}

export async function verifyCrossStationEventProof(
  event: Pick<
    OfflinePendingEvent,
    | 'packageId'
    | 'eventId'
    | 'eventType'
    | 'acceptanceNonce'
    | 'receiverName'
    | 'zone'
    | 'cvvCiphertext'
    | 'cvvIv'
    | 'cvvAuthTag'
    | 'localTimestamp'
    | 'deviceId'
  >,
  proof: CrossStationEventProof | undefined,
  options?: {
    trustedIssuerKeyIds?: string[];
    trustedStationKeyIds?: string[];
    requireStationCert?: boolean;
  }
): Promise<{
  valid: boolean;
  stationVerified: boolean;
  receiverVerified: boolean;
  certVerified: boolean;
  reason: string;
}> {
  if (!proof || proof.version !== OFFLINE_CRYPTO_CONFIG.eventProofVersion) {
    return {
      valid: false,
      stationVerified: false,
      receiverVerified: false,
      certVerified: false,
      reason: 'El evento no incluye prueba criptográfica verificable entre estaciones (ECDSA P-256).',
    };
  }

  try {
    const { publicKey: stationPub, keyId: computedStationKeyId } = await importEcdsaPublicKey(
      proof.stationPublicKeyB64u
    );
    if (computedStationKeyId !== proof.stationKeyId) {
      return {
        valid: false,
        stationVerified: false,
        receiverVerified: false,
        certVerified: false,
        reason: 'La clave pública de la estación no coincide con stationKeyId.',
      };
    }

    let certVerified = false;
    if (proof.stationCert) {
      if (proof.stationCert.stationKeyId !== proof.stationKeyId) {
        return {
          valid: false,
          stationVerified: false,
          receiverVerified: false,
          certVerified: false,
          reason: 'El certificado de estación no pertenece a la clave que firmó el evento.',
        };
      }
      const eventTimeMs = Date.parse(event.localTimestamp);
      const certRes = await verifyStationCertificate(proof.stationCert, {
        trustedIssuerKeyIds: options?.trustedIssuerKeyIds,
        referenceTimeMs: Number.isFinite(eventTimeMs) ? eventTimeMs : Date.now(),
      });
      if (!certRes.valid) {
        return {
          valid: false,
          stationVerified: false,
          receiverVerified: false,
          certVerified: false,
          reason: certRes.reason,
        };
      }
      certVerified = true;
    } else if (options?.requireStationCert) {
      if (
        options.trustedStationKeyIds &&
        options.trustedStationKeyIds.includes(proof.stationKeyId)
      ) {
        certVerified = true;
      } else {
        return {
          valid: false,
          stationVerified: false,
          receiverVerified: false,
          certVerified: false,
          reason: 'Falta certificado de estación autorizada para validar el origen del CVV.',
        };
      }
    }

    let receiverVerified = false;
    if (!proof.acceptanceProof) {
      return {
        valid: false,
        stationVerified: false,
        receiverVerified: false,
        certVerified,
        reason: 'El evento no adjunta la firma criptográfica de aceptación del receptor.',
      };
    }

    const ap = proof.acceptanceProof;
    const { publicKey: receiverPub, keyId: computedRecKeyId } = await importEcdsaPublicKey(
      ap.receiverPublicKeyB64u
    );
    if (computedRecKeyId !== ap.receiverKeyId) {
      return {
        valid: false,
        stationVerified: false,
        receiverVerified: false,
        certVerified,
        reason: 'La clave pública del receptor en la prueba no coincide con receiverKeyId.',
      };
    }

    const expectedAcceptHash = await computeReceiverAcceptanceHash({
      packageId: event.packageId,
      eventType: event.eventType,
      nonce: event.acceptanceNonce,
      receiverUid: ap.receiverUid,
      receiverDeviceId: ap.receiverDeviceId,
      receiverKeyId: ap.receiverKeyId,
      issuedAt: ap.issuedAt,
    });
    if (ap.acceptanceHash !== expectedAcceptHash) {
      return {
        valid: false,
        stationVerified: false,
        receiverVerified: false,
        certVerified,
        reason: 'El hash criptográfico (nonce + hash) ligado a la identidad del receptor no coincide.',
      };
    }

    const acceptCanonical = buildAcceptanceCanonicalString({
      packageId: event.packageId,
      eventType: event.eventType,
      nonce: event.acceptanceNonce,
      receiverName: cleanQrSegment(event.receiverName, 120),
      zone: cleanQrSegment(event.zone, 120),
      receiverUid: ap.receiverUid,
      receiverDeviceId: ap.receiverDeviceId,
      issuedAt: ap.issuedAt,
      acceptanceHash: ap.acceptanceHash,
    });

    const acceptSigOk = await getSubtleCrypto().verify(
      { name: 'ECDSA', hash: 'SHA-256' },
      receiverPub,
      base64UrlDecode(ap.signatureB64u) as BufferSource,
      new TextEncoder().encode(acceptCanonical)
    );
    if (!acceptSigOk) {
      return {
        valid: false,
        stationVerified: false,
        receiverVerified: false,
        certVerified,
        reason: 'La firma del receptor en la prueba de aceptación no es válida.',
      };
    }
    receiverVerified = true;

    const operatorUid = proof.operatorUid || proof.stationCert?.operatorUid || 'LOCAL_OPERATOR';
    const eventCanonical = buildCrossStationEventCanonical({
      packageId: event.packageId,
      eventId: event.eventId,
      eventType: event.eventType,
      acceptanceNonce: event.acceptanceNonce,
      acceptanceSigB64u: ap.signatureB64u,
      cvvCiphertext: event.cvvCiphertext,
      cvvIv: event.cvvIv,
      cvvAuthTag: event.cvvAuthTag,
      localTimestamp: event.localTimestamp,
      deviceId: event.deviceId,
      operatorUid,
    });

    const stationSigOk = await getSubtleCrypto().verify(
      { name: 'ECDSA', hash: 'SHA-256' },
      stationPub,
      base64UrlDecode(proof.stationSignatureB64u) as BufferSource,
      new TextEncoder().encode(eventCanonical)
    );
    if (!stationSigOk) {
      return {
        valid: false,
        stationVerified: false,
        receiverVerified,
        certVerified,
        reason:
          'La firma ECDSA de la estación emisora no coincide con el CVV/ciphertext/timestamp. Posible alteración.',
      };
    }

    return {
      valid: true,
      stationVerified: true,
      receiverVerified: true,
      certVerified,
      reason: `Sello entre estaciones verificado (Estación #${proof.stationKeyId} · Receptor ${ap.receiverUid} #${ap.receiverKeyId}).`,
    };
  } catch {
    return {
      valid: false,
      stationVerified: false,
      receiverVerified: false,
      certVerified: false,
      reason: 'Error verificando la firma criptográfica entre estaciones.',
    };
  }
}

export async function deriveVaultWrappingKey(
  passphrase: string,
  salt: Uint8Array,
  iterations: number = OFFLINE_CRYPTO_CONFIG.pbkdf2Iterations,
  usages: KeyUsage[] = ['encrypt', 'decrypt']
): Promise<CryptoKey> {
  const subtle = getSubtleCrypto();
  const baseKey = await subtle.importKey(
    'raw',
    new TextEncoder().encode(passphrase),
    'PBKDF2',
    false,
    ['deriveKey']
  );

  return subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt: salt as BufferSource,
      iterations,
      hash: 'SHA-256',
    },
    baseKey,
    { name: 'AES-GCM', length: OFFLINE_CRYPTO_CONFIG.aesKeyLengthBits },
    false,
    usages
  );
}

export async function sealOfflineCredentialVault(params: {
  passphrase: string;
  operator: OfflineOperatorIdentity;
  deviceId: string;
  ttlMs?: number;
  issuerSigner?: { privateKey: CryptoKey; publicKeyB64u: string; keyId: string };
}): Promise<{
  vaultEnvelope: OfflineVaultEnvelope;
  sessionKeys: OfflineSessionKeys;
  stationIdentity: { keyId: string; publicKeyB64u: string; stationCert?: StationCertificate };
  issuedAt: string;
  expiresAt: string;
}> {
  if (params.passphrase.trim().length < 8) {
    throw new Error('La clave de protección offline debe tener al menos 8 caracteres.');
  }

  const subtle = getSubtleCrypto();
  const encoder = new TextEncoder();
  const iterations = OFFLINE_CRYPTO_CONFIG.pbkdf2Iterations;
  const salt = globalThis.crypto.getRandomValues(new Uint8Array(16));
  const iv = globalThis.crypto.getRandomValues(new Uint8Array(OFFLINE_CRYPTO_CONFIG.aesGcmIvBytes));
  const wrappingKey = await deriveVaultWrappingKey(params.passphrase, salt, iterations, ['encrypt']);

  // Generate AES-GCM + HMAC + ECDSA P-256 keys for the offline station
  const extractableKeys = await generateOfflineSessionKeys(true);
  const { aesJwk, hmacJwk } = await exportOfflineSessionKeysJwk(extractableKeys);
  const sessionKeys = await importOfflineSessionKeysJwk(aesJwk, hmacJwk, false);

  const ecdsaExtractable = await generateEcdsaIdentityKeyPair(true);
  const ecdsaPrivateJwk = await subtle.exportKey('jwk', ecdsaExtractable.privateKey);

  const issuedAt = new Date().toISOString();
  const expiresAt = new Date(
    Date.now() + (params.ttlMs ?? OFFLINE_CRYPTO_CONFIG.vaultTtlMs)
  ).toISOString();

  const operator: Required<OfflineOperatorIdentity> = {
    uid: params.operator.uid,
    email: params.operator.email,
    displayName:
      params.operator.displayName || params.operator.email.split('@')[0] || 'Operador TAI',
    role: params.operator.role || 'Operador Autorizado Offline',
  };

  let stationCert: StationCertificate | undefined;
  if (params.issuerSigner) {
    stationCert = await issueStationCertificate(
      {
        stationKeyId: ecdsaExtractable.keyId,
        stationPublicKeyB64u: ecdsaExtractable.publicKeyB64u,
        deviceId: params.deviceId,
        operatorUid: operator.uid,
        operatorEmail: operator.email,
        issuedAt,
        expiresAt,
      },
      params.issuerSigner
    );
  }

  const identityCanonical = [
    operator.uid,
    operator.email,
    params.deviceId,
    issuedAt,
    expiresAt,
    ecdsaExtractable.keyId,
  ].join('|');

  const attestationSig = await subtle.sign(
    'HMAC',
    extractableKeys.hmacKey,
    encoder.encode(identityCanonical)
  );

  const vaultPlaintext = {
    v: OFFLINE_CRYPTO_CONFIG.vaultVersion,
    operator,
    deviceId: params.deviceId,
    issuedAt,
    expiresAt,
    stationKeyId: ecdsaExtractable.keyId,
    stationPublicKeyB64u: ecdsaExtractable.publicKeyB64u,
    ...(stationCert ? { stationCert } : {}),
    authAttestation: bytesToHex(new Uint8Array(attestationSig)),
    keys: {
      aesJwk,
      hmacJwk,
      ecdsaPrivateJwk,
    },
  };

  const encryptedBuf = await subtle.encrypt(
    {
      name: 'AES-GCM',
      iv: iv as BufferSource,
      additionalData: encoder.encode(OFFLINE_CRYPTO_CONFIG.vaultVersion),
      tagLength: OFFLINE_CRYPTO_CONFIG.aesGcmTagLengthBits,
    },
    wrappingKey,
    encoder.encode(JSON.stringify(vaultPlaintext))
  );

  return {
    vaultEnvelope: {
      version: OFFLINE_CRYPTO_CONFIG.vaultVersion,
      algorithm: OFFLINE_CRYPTO_CONFIG.algorithmLabel,
      iterations,
      saltHex: bytesToHex(salt),
      ivHex: bytesToHex(iv),
      ciphertextHex: bytesToHex(new Uint8Array(encryptedBuf)),
      expiresAt,
      stationKeyId: ecdsaExtractable.keyId,
      ...(stationCert ? { stationCert } : {}),
    },
    sessionKeys,
    stationIdentity: {
      keyId: ecdsaExtractable.keyId,
      publicKeyB64u: ecdsaExtractable.publicKeyB64u,
      ...(stationCert ? { stationCert } : {}),
    },
    issuedAt,
    expiresAt,
  };
}

export async function unlockOfflineCredentialVault(
  vaultEnvelope: OfflineVaultEnvelope,
  passphrase: string
): Promise<UnlockedOfflineSession> {
  const subtle = getSubtleCrypto();
  const encoder = new TextEncoder();
  const salt = hexToBytes(vaultEnvelope.saltHex);
  const iv = hexToBytes(vaultEnvelope.ivHex);
  const ciphertext = hexToBytes(vaultEnvelope.ciphertextHex);

  const wrappingKey = await deriveVaultWrappingKey(
    passphrase,
    salt,
    vaultEnvelope.iterations || OFFLINE_CRYPTO_CONFIG.pbkdf2Iterations,
    ['decrypt']
  );

  const plainBuf = await subtle.decrypt(
    {
      name: 'AES-GCM',
      iv: iv as BufferSource,
      additionalData: encoder.encode(OFFLINE_CRYPTO_CONFIG.vaultVersion),
      tagLength: OFFLINE_CRYPTO_CONFIG.aesGcmTagLengthBits,
    },
    wrappingKey,
    ciphertext as BufferSource
  );

  const vaultData = JSON.parse(new TextDecoder().decode(plainBuf)) as {
    v: string;
    operator: Required<OfflineOperatorIdentity>;
    deviceId: string;
    issuedAt: string;
    expiresAt: string;
    stationKeyId: string;
    stationPublicKeyB64u: string;
    stationCert?: StationCertificate;
    authAttestation: string;
    keys: { aesJwk: JsonWebKey; hmacJwk: JsonWebKey; ecdsaPrivateJwk: JsonWebKey };
  };

  if (!vaultData || vaultData.v !== OFFLINE_CRYPTO_CONFIG.vaultVersion) {
    throw new Error('Formato de bóveda offline inválido.');
  }
  if (Date.now() > Date.parse(vaultData.expiresAt)) {
    throw new Error(
      'La credencial offline ha expirado. Descarga una nueva estación desde la plataforma.'
    );
  }

  const [keys, ecdsaPrivateKey] = await Promise.all([
    importOfflineSessionKeysJwk(vaultData.keys.aesJwk, vaultData.keys.hmacJwk, false),
    subtle.importKey(
      'jwk',
      vaultData.keys.ecdsaPrivateJwk,
      { name: 'ECDSA', namedCurve: 'P-256' },
      false,
      ['sign']
    ),
  ]);

  const canonical = [
    vaultData.operator.uid,
    vaultData.operator.email,
    vaultData.deviceId,
    vaultData.issuedAt,
    vaultData.expiresAt,
    vaultData.stationKeyId,
  ].join('|');

  const sigValid = await subtle.verify(
    'HMAC',
    keys.hmacKey,
    hexToBytes(vaultData.authAttestation) as BufferSource,
    encoder.encode(canonical)
  );
  if (!sigValid) {
    throw new Error('La firma HMAC de autenticación del operador no es válida.');
  }

  return {
    operator: vaultData.operator,
    deviceId: vaultData.deviceId,
    issuedAt: vaultData.issuedAt,
    expiresAt: vaultData.expiresAt,
    keys,
    ecdsa: {
      privateKey: ecdsaPrivateKey,
      publicKeyB64u: vaultData.stationPublicKeyB64u,
      keyId: vaultData.stationKeyId,
      stationCert: vaultData.stationCert,
    },
  };
}

export function buildCsgCanonicalString(params: {
  packageId: string;
  eventId: string;
  eventType: string;
  acceptanceNonce: string;
  authTag: string;
}): string {
  return [
    params.packageId,
    params.eventId,
    params.eventType,
    params.acceptanceNonce,
    params.authTag,
  ].join('|');
}

export async function sealTransferEventOffline(
  input: OfflineTransferSealInput,
  keys: OfflineSessionKeys
): Promise<OfflineTransferSealOutput> {
  const subtle = getSubtleCrypto();
  const encoder = new TextEncoder();

  const eventId = (input.eventId || generateOfflineEventId())
    .replace(/[^a-zA-Z0-9_-]/g, '_')
    .slice(0, 128);
  const payload = {
    v: OFFLINE_CRYPTO_CONFIG.cvvPayloadVersion,
    csgProviderId: ACTIVE_CSG_PROVIDER.providerId,
    packageId: input.packageId.slice(0, 64),
    eventId,
    eventType: input.eventType,
    delivererName: input.delivererName.slice(0, 120),
    receiverName: input.receiverName.slice(0, 120),
    zone: input.zone.slice(0, 120),
    functionRole: input.functionRole.slice(0, 120),
    acceptanceNonce: input.acceptanceNonce.slice(0, 128),
    localTimestamp: input.localTimestamp.slice(0, 64),
    observations: input.observations.slice(0, 500),
    capturedOffline: input.capturedOffline ?? true,
    deviceId: input.deviceId.slice(0, 64),
    ...(input.operatorUid ? { operatorUid: input.operatorUid.slice(0, 128) } : {}),
    ...(input.operatorEmail ? { operatorEmail: input.operatorEmail.slice(0, 120) } : {}),
    ...(input.acceptanceProof
      ? {
          receiverUid: input.acceptanceProof.receiverUid,
          receiverDeviceId: input.acceptanceProof.receiverDeviceId,
          receiverKeyId: input.acceptanceProof.receiverKeyId,
          receiverSignature: input.acceptanceProof.signatureB64u,
          acceptanceHash: input.acceptanceProof.acceptanceHash,
          acceptanceCryptoId: input.acceptanceProof.acceptanceCryptoId,
        }
      : {}),
  };

  const iv = globalThis.crypto.getRandomValues(new Uint8Array(OFFLINE_CRYPTO_CONFIG.aesGcmIvBytes));
  const aad = encoder.encode(`${payload.packageId}:${payload.eventId}`);
  const encryptedBuf = await subtle.encrypt(
    {
      name: 'AES-GCM',
      iv: iv as BufferSource,
      additionalData: aad,
      tagLength: OFFLINE_CRYPTO_CONFIG.aesGcmTagLengthBits,
    },
    keys.aesKey,
    encoder.encode(JSON.stringify(payload))
  );

  const encBytes = new Uint8Array(encryptedBuf);
  const tagByteLen = OFFLINE_CRYPTO_CONFIG.aesGcmTagLengthBits / 8;
  const ciphertextBytes = encBytes.slice(0, encBytes.length - tagByteLen);
  const authTagBytes = encBytes.slice(encBytes.length - tagByteLen);

  const authTagHex = bytesToHex(authTagBytes);
  const canonical = buildCsgCanonicalString({
    packageId: payload.packageId,
    eventId: payload.eventId,
    eventType: payload.eventType,
    acceptanceNonce: payload.acceptanceNonce,
    authTag: authTagHex,
  });

  const csgBuf = await subtle.sign('HMAC', keys.hmacKey, encoder.encode(canonical));

  return {
    eventId,
    ciphertext: bytesToHex(ciphertextBytes),
    iv: bytesToHex(iv),
    authTag: authTagHex,
    csgSeal: bytesToHex(new Uint8Array(csgBuf)),
    algorithm: `WebCrypto ${OFFLINE_CRYPTO_CONFIG.algorithmLabel} (Offline)`,
  };
}

export async function verifyTransferEventOffline(
  params: {
    ciphertext: string;
    iv: string;
    authTag: string;
    csgSeal: string;
    packageId: string;
    eventId: string;
    eventType: string;
    acceptanceNonce: string;
  },
  keys: OfflineSessionKeys
): Promise<OfflineCsgVerifyResult> {
  try {
    const subtle = getSubtleCrypto();
    const encoder = new TextEncoder();

    const canonical = buildCsgCanonicalString({
      packageId: params.packageId,
      eventId: params.eventId,
      eventType: params.eventType,
      acceptanceNonce: params.acceptanceNonce,
      authTag: params.authTag,
    });

    const sigValid = await subtle.verify(
      'HMAC',
      keys.hmacKey,
      hexToBytes(params.csgSeal) as BufferSource,
      encoder.encode(canonical)
    );

    if (!sigValid) {
      return {
        valid: false,
        csgStatus: 'OUT_OF_FLOW',
        reason:
          'Sello HMAC local incompatible o alterado (OUT_OF_FLOW). El registro maestro se conserva intacto.',
      };
    }

    const ctBytes = hexToBytes(params.ciphertext);
    const tagBytes = hexToBytes(params.authTag);
    const combined = new Uint8Array(ctBytes.length + tagBytes.length);
    combined.set(ctBytes, 0);
    combined.set(tagBytes, ctBytes.length);

    const plainBuf = await subtle.decrypt(
      {
        name: 'AES-GCM',
        iv: hexToBytes(params.iv) as BufferSource,
        additionalData: encoder.encode(`${params.packageId}:${params.eventId}`),
        tagLength: OFFLINE_CRYPTO_CONFIG.aesGcmTagLengthBits,
      },
      keys.aesKey,
      combined
    );

    const decryptedPayload = JSON.parse(new TextDecoder().decode(plainBuf)) as Record<
      string,
      unknown
    >;

    return {
      valid: true,
      csgStatus: 'VERIFIED',
      decryptedPayload,
      reason: 'VERIFIED (AES-256-GCM + HMAC local): Integridad verificada localmente.',
    };
  } catch {
    return {
      valid: false,
      csgStatus: 'INVALIDATED_TAMPERED',
      reason: 'INVALIDATED_TAMPERED: Fallo de autenticación AES-256-GCM.',
    };
  }
}

export async function encryptOfflineQueueBlob(
  items: unknown,
  keys: Pick<OfflineSessionKeys, 'aesKey'>,
  aadContext: string
): Promise<{ iv: string; ct: string }> {
  const subtle = getSubtleCrypto();
  const encoder = new TextEncoder();
  const iv = globalThis.crypto.getRandomValues(new Uint8Array(OFFLINE_CRYPTO_CONFIG.aesGcmIvBytes));
  const encryptedBuf = await subtle.encrypt(
    {
      name: 'AES-GCM',
      iv: iv as BufferSource,
      additionalData: encoder.encode(aadContext),
      tagLength: OFFLINE_CRYPTO_CONFIG.aesGcmTagLengthBits,
    },
    keys.aesKey,
    encoder.encode(JSON.stringify(items))
  );
  return {
    iv: bytesToHex(iv),
    ct: bytesToHex(new Uint8Array(encryptedBuf)),
  };
}

export async function decryptOfflineQueueBlob<T>(
  blob: { iv: string; ct: string },
  keys: Pick<OfflineSessionKeys, 'aesKey'>,
  aadContext: string
): Promise<T> {
  const subtle = getSubtleCrypto();
  const plainBuf = await subtle.decrypt(
    {
      name: 'AES-GCM',
      iv: hexToBytes(blob.iv) as BufferSource,
      additionalData: new TextEncoder().encode(aadContext),
      tagLength: OFFLINE_CRYPTO_CONFIG.aesGcmTagLengthBits,
    },
    keys.aesKey,
    hexToBytes(blob.ct) as BufferSource
  );
  return JSON.parse(new TextDecoder().decode(plainBuf)) as T;
}

/**
 * Generates a zero-dependency browser Web Crypto runtime script (`window.TaiOfflineCrypto`)
 * for standalone offline HTML exports so acceptance QR signing, receiver verification,
 * AES-256-GCM + HMAC + ECDSA P-256 CVV sealing, and cross-station verification run locally
 * without Firestore or external servers.
 */
export function buildOfflineCryptoBrowserRuntime(): string {
  const runtime = `(function (global) {
  "use strict";
  var VAULT_VERSION = ${JSON.stringify(OFFLINE_CRYPTO_CONFIG.vaultVersion)};
  var CVV_VERSION = ${JSON.stringify(OFFLINE_CRYPTO_CONFIG.cvvPayloadVersion)};
  var ACCEPT_VERSION = ${JSON.stringify(OFFLINE_CRYPTO_CONFIG.acceptQrVersion)};
  var PROOF_VERSION = ${JSON.stringify(OFFLINE_CRYPTO_CONFIG.eventProofVersion)};
  var CSG_PROVIDER_ID = ${JSON.stringify(ACTIVE_CSG_PROVIDER.providerId)};
  var DEFAULT_ITERATIONS = ${OFFLINE_CRYPTO_CONFIG.pbkdf2Iterations};
  var GCM_TAG_BITS = ${OFFLINE_CRYPTO_CONFIG.aesGcmTagLengthBits};
  var ACCEPT_MAX_AGE_MS = ${OFFLINE_CRYPTO_CONFIG.acceptanceMaxAgeMs};

  function cleanSegment(val, maxLen) {
    return String(val || "").replace(/\\|/g, "/").replace(/[\\r\\n]/g, " ").trim().slice(0, maxLen || 120);
  }

  function bytesToHex(bytes) {
    return Array.from(bytes).map(function (b) { return b.toString(16).padStart(2, "0"); }).join("");
  }

  function hexToBytes(hex) {
    var clean = String(hex || "").trim();
    if (clean.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(clean)) {
      throw new Error("Cadena hexadecimal inválida.");
    }
    var out = new Uint8Array(clean.length / 2);
    for (var i = 0; i < out.length; i++) {
      out[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
    }
    return out;
  }

  function base64UrlEncode(bytes) {
    var bin = "";
    for (var i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
    return btoa(bin).replace(/\\+/g, "-").replace(/\\//g, "_").replace(/=+$/g, "");
  }

  function base64UrlDecode(str) {
    var clean = String(str || "").trim().replace(/-/g, "+").replace(/_/g, "/");
    var pad = clean.length % 4 === 0 ? "" : "=".repeat(4 - (clean.length % 4));
    var bin = atob(clean + pad);
    var out = new Uint8Array(bin.length);
    for (var i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }

  async function computeKeyThumbprint(spkiBytes) {
    var digest = await crypto.subtle.digest("SHA-256", spkiBytes);
    return bytesToHex(new Uint8Array(digest)).slice(0, 16).toUpperCase();
  }

  async function importEcdsaPublicKey(pubB64u) {
    var spki = base64UrlDecode(pubB64u);
    var key = await crypto.subtle.importKey("spki", spki, { name: "ECDSA", namedCurve: "P-256" }, true, ["verify"]);
    var keyId = await computeKeyThumbprint(spki);
    return { publicKey: key, keyId: keyId };
  }

  function generateNonce() {
    var rnd = crypto.getRandomValues(new Uint8Array(4));
    return "ACC_" + Date.now().toString(36).toUpperCase() + "_" + bytesToHex(rnd).toUpperCase();
  }

  function generateEventId() {
    var rnd = crypto.getRandomValues(new Uint8Array(4));
    return "CVV_OFF_" + Date.now().toString(36).toUpperCase() + "_" + bytesToHex(rnd).toUpperCase();
  }

  async function unlockVault(vault, passphrase) {
    var enc = new TextEncoder();
    var salt = hexToBytes(vault.saltHex);
    var iv = hexToBytes(vault.ivHex);
    var ct = hexToBytes(vault.ciphertextHex);

    var baseKey = await crypto.subtle.importKey("raw", enc.encode(passphrase), "PBKDF2", false, ["deriveKey"]);
    var wrapKey = await crypto.subtle.deriveKey(
      { name: "PBKDF2", salt: salt, iterations: vault.iterations || DEFAULT_ITERATIONS, hash: "SHA-256" },
      baseKey,
      { name: "AES-GCM", length: 256 },
      false,
      ["decrypt"]
    );

    var plainBuf = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: iv, additionalData: enc.encode(VAULT_VERSION), tagLength: GCM_TAG_BITS },
      wrapKey,
      ct
    );

    var vaultData = JSON.parse(new TextDecoder().decode(plainBuf));
    if (!vaultData || vaultData.v !== VAULT_VERSION) {
      throw new Error("Formato de bóveda inválido.");
    }
    if (Date.now() > Date.parse(vaultData.expiresAt)) {
      throw new Error("La credencial offline ha expirado. Descarga una nueva estación desde la plataforma.");
    }

    var aesKey = await crypto.subtle.importKey(
      "jwk",
      vaultData.keys.aesJwk,
      { name: "AES-GCM", length: 256 },
      false,
      ["encrypt", "decrypt"]
    );
    var hmacKey = await crypto.subtle.importKey(
      "jwk",
      vaultData.keys.hmacJwk,
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["sign", "verify"]
    );
    var ecdsaPrivateKey = await crypto.subtle.importKey(
      "jwk",
      vaultData.keys.ecdsaPrivateJwk,
      { name: "ECDSA", namedCurve: "P-256" },
      false,
      ["sign"]
    );

    var canonical = [
      vaultData.operator.uid,
      vaultData.operator.email,
      vaultData.deviceId,
      vaultData.issuedAt,
      vaultData.expiresAt,
      vaultData.stationKeyId
    ].join("|");

    var validSig = await crypto.subtle.verify(
      "HMAC",
      hmacKey,
      hexToBytes(vaultData.authAttestation),
      enc.encode(canonical)
    );
    if (!validSig) {
      throw new Error("La firma de autenticación del operador no es válida.");
    }

    return {
      operator: vaultData.operator,
      deviceId: vaultData.deviceId,
      issuedAt: vaultData.issuedAt,
      expiresAt: vaultData.expiresAt,
      stationKeyId: vaultData.stationKeyId,
      stationPublicKeyB64u: vaultData.stationPublicKeyB64u,
      stationCert: vaultData.stationCert || null,
      aesKey: aesKey,
      hmacKey: hmacKey,
      ecdsaPrivateKey: ecdsaPrivateKey,
      storageKey: "tai_off_q_" + vault.saltHex.slice(0, 16)
    };
  }

  async function computeAcceptanceHash(p) {
    var canonical = [
      "TAI-ACCEPT-ID-V1",
      p.packageId,
      p.eventType,
      p.nonce,
      p.receiverUid,
      p.receiverDeviceId,
      p.keyId,
      p.issuedAt
    ].join("|");
    var digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(canonical));
    return bytesToHex(new Uint8Array(digest));
  }

  function formatCryptoId(nonce, hashHex) {
    return nonce + ":" + hashHex.slice(0, 16).toUpperCase();
  }

  function buildAcceptCanonical(p) {
    return [
      ACCEPT_VERSION,
      p.packageId,
      p.eventType,
      p.nonce,
      p.receiverName,
      p.zone,
      p.receiverUid,
      p.receiverDeviceId,
      p.issuedAt,
      p.acceptanceHash
    ].join("|");
  }

  async function signAcceptanceQr(params, session) {
    var issuedAt = params.issuedAt || new Date().toISOString();
    var p = {
      packageId: cleanSegment(params.packageId, 64),
      eventType: params.eventType,
      nonce: cleanSegment(params.nonce, 128),
      receiverName: cleanSegment(params.receiverName || session.operator.displayName, 120),
      zone: cleanSegment(params.zone || "Centro Logístico Buenos Aires", 120),
      receiverUid: cleanSegment(session.operator.uid, 128),
      receiverDeviceId: cleanSegment(session.deviceId, 64),
      issuedAt: issuedAt,
      keyId: session.stationKeyId
    };
    p.acceptanceHash = await computeAcceptanceHash(p);
    var acceptanceCryptoId = formatCryptoId(p.nonce, p.acceptanceHash);
    var canonical = buildAcceptCanonical(p);
    var sigBuf = await crypto.subtle.sign(
      { name: "ECDSA", hash: "SHA-256" },
      session.ecdsaPrivateKey,
      new TextEncoder().encode(canonical)
    );
    var sigB64u = base64UrlEncode(new Uint8Array(sigBuf));
    var qrString = [
      "tai://accept",
      p.packageId,
      p.eventType,
      p.nonce,
      p.receiverName,
      p.zone,
      p.receiverUid,
      p.receiverDeviceId,
      p.issuedAt,
      session.stationKeyId,
      sigB64u,
      session.stationPublicKeyB64u,
      p.acceptanceHash
    ].join("|");

    return {
      qrString: qrString,
      acceptanceHash: p.acceptanceHash,
      acceptanceCryptoId: acceptanceCryptoId,
      proof: {
        version: ACCEPT_VERSION,
        receiverUid: p.receiverUid,
        receiverDeviceId: p.receiverDeviceId,
        receiverKeyId: session.stationKeyId,
        receiverPublicKeyB64u: session.stationPublicKeyB64u,
        issuedAt: p.issuedAt,
        acceptanceHash: p.acceptanceHash,
        acceptanceCryptoId: acceptanceCryptoId,
        signatureB64u: sigB64u
      }
    };
  }

  async function parseAndVerifyAcceptanceQr(raw) {
    var trimmed = String(raw || "").trim();
    if (trimmed.indexOf("tai://accept|") !== 0) {
      return { valid: false, reason: "El código escaneado no es un QR de aceptación TAI válido." };
    }
    var parts = trimmed.split("|");
    if (parts.length < 13) {
      return { valid: false, reason: "El QR de aceptación no incluye identificador (nonce + hash) y firma ECDSA del receptor." };
    }
    var p = {
      packageId: (parts[1] || "").trim(),
      eventType: (parts[2] || "").trim(),
      nonce: (parts[3] || "").trim(),
      receiverName: (parts[4] || "").trim() || "Receptor en sitio",
      zone: (parts[5] || "").trim() || "Centro Logístico Buenos Aires",
      receiverUid: (parts[6] || "").trim(),
      receiverDeviceId: (parts[7] || "").trim(),
      issuedAt: (parts[8] || "").trim(),
      keyId: (parts[9] || "").trim(),
      signatureB64u: (parts[10] || "").trim(),
      publicKeyB64u: (parts[11] || "").trim(),
      acceptanceHash: (parts[12] || "").trim().toLowerCase()
    };
    if (!p.packageId || (p.eventType !== "dispatch" && p.eventType !== "receive" && p.eventType !== "return") ||
        p.nonce.length < 4 || !p.receiverUid || !p.receiverDeviceId || !p.issuedAt || !p.keyId || !p.signatureB64u || !p.publicKeyB64u ||
        !/^[0-9a-f]{64}$/.test(p.acceptanceHash)) {
      return { valid: false, reason: "El QR firmado contiene campos o hash SHA-256 inválidos." };
    }
    var issuedMs = Date.parse(p.issuedAt);
    if (!isFinite(issuedMs) || Date.now() - issuedMs > ACCEPT_MAX_AGE_MS || issuedMs > Date.now() + 300000) {
      return { valid: false, reason: "El QR de aceptación está expirado o fuera de ventana temporal." };
    }
    try {
      var imported = await importEcdsaPublicKey(p.publicKeyB64u);
      if (imported.keyId !== p.keyId) {
        return { valid: false, reason: "La huella de clave del receptor no coincide." };
      }
      var expectedHash = await computeAcceptanceHash(p);
      if (expectedHash !== p.acceptanceHash) {
        return { valid: false, reason: "El identificador (nonce + hash) no corresponde a la identidad del receptor." };
      }
      var acceptanceCryptoId = formatCryptoId(p.nonce, p.acceptanceHash);
      var canonical = buildAcceptCanonical(p);
      var ok = await crypto.subtle.verify(
        { name: "ECDSA", hash: "SHA-256" },
        imported.publicKey,
        base64UrlDecode(p.signatureB64u),
        new TextEncoder().encode(canonical)
      );
      if (!ok) {
        return { valid: false, reason: "Firma ECDSA del receptor inválida o QR adulterado." };
      }
      return {
        valid: true,
        parsed: {
          packageId: p.packageId,
          eventType: p.eventType,
          nonce: p.nonce,
          acceptanceHash: p.acceptanceHash,
          acceptanceCryptoId: acceptanceCryptoId,
          receiverName: p.receiverName,
          zone: p.zone,
          receiverUid: p.receiverUid,
          receiverDeviceId: p.receiverDeviceId,
          issuedAt: p.issuedAt,
          proof: {
            version: ACCEPT_VERSION,
            receiverUid: p.receiverUid,
            receiverDeviceId: p.receiverDeviceId,
            receiverKeyId: p.keyId,
            receiverPublicKeyB64u: p.publicKeyB64u,
            issuedAt: p.issuedAt,
            acceptanceHash: p.acceptanceHash,
            acceptanceCryptoId: acceptanceCryptoId,
            signatureB64u: p.signatureB64u
          }
        },
        reason: "Receptor verificado (" + p.receiverUid + " · " + acceptanceCryptoId + " · #" + p.keyId + ")"
      };
    } catch (err) {
      return { valid: false, reason: "No se pudo verificar la firma ECDSA del receptor." };
    }
  }

  async function sealTransferEvent(input, session) {
    var enc = new TextEncoder();
    var eventId = input.eventId || generateEventId();
    var payload = {
      v: CVV_VERSION,
      csgProviderId: CSG_PROVIDER_ID,
      packageId: String(input.packageId || "").slice(0, 64),
      eventId: eventId,
      eventType: input.eventType,
      delivererName: String(input.delivererName || "").slice(0, 120),
      receiverName: String(input.receiverName || "").slice(0, 120),
      zone: String(input.zone || "").slice(0, 120),
      functionRole: String(input.functionRole || "").slice(0, 120),
      acceptanceNonce: String(input.acceptanceNonce || "").slice(0, 128),
      acceptanceHash: input.acceptanceProof ? input.acceptanceProof.acceptanceHash : "",
      acceptanceCryptoId: input.acceptanceProof ? input.acceptanceProof.acceptanceCryptoId : "",
      localTimestamp: String(input.localTimestamp || "").slice(0, 64),
      observations: String(input.observations || "").slice(0, 500),
      capturedOffline: true,
      deviceId: session.deviceId,
      operatorUid: session.operator.uid,
      operatorEmail: session.operator.email,
      receiverUid: input.acceptanceProof ? input.acceptanceProof.receiverUid : "",
      receiverDeviceId: input.acceptanceProof ? input.acceptanceProof.receiverDeviceId : "",
      receiverKeyId: input.acceptanceProof ? input.acceptanceProof.receiverKeyId : "",
      receiverSignature: input.acceptanceProof ? input.acceptanceProof.signatureB64u : ""
    };

    var iv = crypto.getRandomValues(new Uint8Array(12));
    var aad = enc.encode(payload.packageId + ":" + payload.eventId);
    var encryptedBuf = await crypto.subtle.encrypt(
      { name: "AES-GCM", iv: iv, additionalData: aad, tagLength: GCM_TAG_BITS },
      session.aesKey,
      enc.encode(JSON.stringify(payload))
    );

    var encBytes = new Uint8Array(encryptedBuf);
    var ctBytes = encBytes.slice(0, encBytes.length - 16);
    var tagBytes = encBytes.slice(encBytes.length - 16);
    var cvvCiphertext = bytesToHex(ctBytes);
    var cvvIv = bytesToHex(iv);
    var authTagHex = bytesToHex(tagBytes);

    var canonical = [payload.packageId, payload.eventId, payload.eventType, payload.acceptanceNonce, authTagHex].join("|");
    var csgBuf = await crypto.subtle.sign("HMAC", session.hmacKey, enc.encode(canonical));

    var eventCanonical = [
      PROOF_VERSION,
      payload.packageId,
      payload.eventId,
      payload.eventType,
      payload.acceptanceNonce,
      input.acceptanceProof ? input.acceptanceProof.signatureB64u : "NO_ACCEPTANCE_SIG",
      cvvCiphertext,
      cvvIv,
      authTagHex,
      payload.localTimestamp,
      session.deviceId,
      session.operator.uid
    ].join("|");

    var stationSigBuf = await crypto.subtle.sign(
      { name: "ECDSA", hash: "SHA-256" },
      session.ecdsaPrivateKey,
      enc.encode(eventCanonical)
    );

    var proof = {
      version: PROOF_VERSION,
      csgProviderId: CSG_PROVIDER_ID,
      stationKeyId: session.stationKeyId,
      stationPublicKeyB64u: session.stationPublicKeyB64u,
      stationSignatureB64u: base64UrlEncode(new Uint8Array(stationSigBuf)),
      operatorUid: session.operator.uid,
      operatorEmail: session.operator.email
    };
    if (session.stationCert) proof.stationCert = session.stationCert;
    if (input.acceptanceProof) proof.acceptanceProof = input.acceptanceProof;

    return {
      eventId: eventId,
      cvvCiphertext: cvvCiphertext,
      cvvIv: cvvIv,
      cvvAuthTag: authTagHex,
      csgSeal: bytesToHex(new Uint8Array(csgBuf)),
      proof: proof
    };
  }

  async function verifyTransferEvent(item, session, simulateTamper) {
    try {
      var enc = new TextEncoder();
      var authTag = simulateTamper ? (item.cvvAuthTag.slice(0, -4) + "ffff") : item.cvvAuthTag;
      var canonical = [item.packageId, item.eventId, item.eventType, item.acceptanceNonce, authTag].join("|");
      var sigOk = await crypto.subtle.verify("HMAC", session.hmacKey, hexToBytes(item.csgSeal), enc.encode(canonical));
      if (!sigOk) {
        return {
          valid: false,
          csgStatus: "OUT_OF_FLOW",
          reason: "OUT_OF_FLOW / INVALIDATED: El sello HMAC local no coincide tras la alteración simulada. El registro maestro se conserva intacto."
        };
      }

      var ctBytes = hexToBytes(item.cvvCiphertext);
      var tagBytes = hexToBytes(authTag);
      var combined = new Uint8Array(ctBytes.length + tagBytes.length);
      combined.set(ctBytes, 0);
      combined.set(tagBytes, ctBytes.length);

      var plainBuf = await crypto.subtle.decrypt(
        { name: "AES-GCM", iv: hexToBytes(item.cvvIv), additionalData: enc.encode(item.packageId + ":" + item.eventId), tagLength: GCM_TAG_BITS },
        session.aesKey,
        combined
      );
      var payload = JSON.parse(new TextDecoder().decode(plainBuf));
      return {
        valid: true,
        csgStatus: "VERIFIED",
        decryptedPayload: payload,
        reason: "VERIFIED (AES-256-GCM + ECDSA P-256 + HMAC): Operador " + payload.operatorEmail + " · Receptor verificado " + (payload.receiverUid || "N/A") + " · Estación #" + (item.proof ? item.proof.stationKeyId : session.stationKeyId)
      };
    } catch (err) {
      return {
        valid: false,
        csgStatus: "INVALIDATED_TAMPERED",
        reason: "INVALIDATED_TAMPERED: Fallo de autenticación AES-256-GCM."
      };
    }
  }

  async function encryptQueueBlob(items, session) {
    var enc = new TextEncoder();
    var iv = crypto.getRandomValues(new Uint8Array(12));
    var ct = await crypto.subtle.encrypt(
      { name: "AES-GCM", iv: iv, additionalData: enc.encode(session.deviceId), tagLength: GCM_TAG_BITS },
      session.aesKey,
      enc.encode(JSON.stringify(items))
    );
    return { iv: bytesToHex(iv), ct: bytesToHex(new Uint8Array(ct)) };
  }

  async function decryptQueueBlob(blob, session) {
    var dec = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: hexToBytes(blob.iv), additionalData: new TextEncoder().encode(session.deviceId), tagLength: GCM_TAG_BITS },
      session.aesKey,
      hexToBytes(blob.ct)
    );
    return JSON.parse(new TextDecoder().decode(dec));
  }

  global.TaiOfflineCrypto = {
    bytesToHex: bytesToHex,
    hexToBytes: hexToBytes,
    generateNonce: generateNonce,
    generateEventId: generateEventId,
    unlockVault: unlockVault,
    signAcceptanceQr: signAcceptanceQr,
    parseAndVerifyAcceptanceQr: parseAndVerifyAcceptanceQr,
    sealTransferEvent: sealTransferEvent,
    verifyTransferEvent: verifyTransferEvent,
    encryptQueueBlob: encryptQueueBlob,
    decryptQueueBlob: decryptQueueBlob
  };
})(window);`;

  return runtime.replace(/<\/script/gi, '<\\/script');
}
