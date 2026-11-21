import {
  base64UrlEncode,
  computeKeyThumbprint,
  decryptOfflineQueueBlob,
  encryptOfflineQueueBlob,
  generateEcdsaIdentityKeyPair,
} from './offlineCrypto';
import type { TraceEventType } from '../types/tai';

const DB_NAME = 'tai_device_keystore_v1';
const STORE_NAME = 'keys';
const AES_KEY_ID = 'tai_aes_256_gcm_key';
const HMAC_KEY_ID = 'tai_csg_hmac_sha256_key';
const ECDSA_PRIV_ID = 'tai_ecdsa_p256_private_key';
const ECDSA_PUB_ID = 'tai_ecdsa_p256_public_key';

interface DeviceKeys {
  aesKey: CryptoKey;
  hmacKey: CryptoKey;
}

export interface DeviceSigningIdentity {
  privateKey: CryptoKey;
  publicKey: CryptoKey;
  publicKeyB64u: string;
  keyId: string;
}

let inMemoryFallbackKeys: DeviceKeys | null = null;
let inMemorySigningIdentity: DeviceSigningIdentity | null = null;

function openKeyDb(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    if (typeof indexedDB === 'undefined') {
      reject(new Error('IndexedDB unavailable'));
      return;
    }
    const req = indexedDB.open(DB_NAME, 1);
    req.onupgradeneeded = () => {
      const db = req.result;
      if (!db.objectStoreNames.contains(STORE_NAME)) {
        db.createObjectStore(STORE_NAME);
      }
    };
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

function idbGet<T>(db: IDBDatabase, key: string): Promise<T | undefined> {
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE_NAME, 'readonly');
    const store = tx.objectStore(STORE_NAME);
    const req = store.get(key);
    req.onsuccess = () => resolve(req.result as T | undefined);
    req.onerror = () => reject(req.error);
  });
}

function idbPut(db: IDBDatabase, key: string, value: unknown): Promise<void> {
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE_NAME, 'readwrite');
    const store = tx.objectStore(STORE_NAME);
    const req = store.put(value, key);
    req.onsuccess = () => resolve();
    req.onerror = () => reject(req.error);
  });
}

async function getOrCreateDeviceKeys(): Promise<DeviceKeys> {
  if (inMemoryFallbackKeys) return inMemoryFallbackKeys;

  try {
    const db = await openKeyDb();
    let aesKey = await idbGet<CryptoKey>(db, AES_KEY_ID);
    let hmacKey = await idbGet<CryptoKey>(db, HMAC_KEY_ID);

    if (!aesKey) {
      aesKey = await crypto.subtle.generateKey(
        { name: 'AES-GCM', length: 256 },
        false,
        ['encrypt', 'decrypt']
      );
      await idbPut(db, AES_KEY_ID, aesKey);
    }

    if (!hmacKey) {
      hmacKey = await crypto.subtle.generateKey(
        { name: 'HMAC', hash: 'SHA-256', length: 256 },
        false,
        ['sign', 'verify']
      );
      await idbPut(db, HMAC_KEY_ID, hmacKey);
    }

    inMemoryFallbackKeys = { aesKey, hmacKey };
    return inMemoryFallbackKeys;
  } catch {
    const aesKey = await crypto.subtle.generateKey(
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt']
    );
    const hmacKey = await crypto.subtle.generateKey(
      { name: 'HMAC', hash: 'SHA-256', length: 256 },
      false,
      ['sign', 'verify']
    );
    inMemoryFallbackKeys = { aesKey, hmacKey };
    return inMemoryFallbackKeys;
  }
}

export async function getDeviceSigningIdentity(): Promise<DeviceSigningIdentity> {
  if (inMemorySigningIdentity) return inMemorySigningIdentity;

  try {
    const db = await openKeyDb();
    let privateKey = await idbGet<CryptoKey>(db, ECDSA_PRIV_ID);
    let publicKey = await idbGet<CryptoKey>(db, ECDSA_PUB_ID);

    if (!privateKey || !publicKey) {
      const generated = await generateEcdsaIdentityKeyPair(false);
      privateKey = generated.privateKey;
      publicKey = generated.publicKey;
      await idbPut(db, ECDSA_PRIV_ID, privateKey);
      await idbPut(db, ECDSA_PUB_ID, publicKey);
    }

    const spki = new Uint8Array(await crypto.subtle.exportKey('spki', publicKey));
    const publicKeyB64u = base64UrlEncode(spki);
    const keyId = await computeKeyThumbprint(spki);

    inMemorySigningIdentity = {
      privateKey,
      publicKey,
      publicKeyB64u,
      keyId,
    };
    return inMemorySigningIdentity;
  } catch {
    const generated = await generateEcdsaIdentityKeyPair(false);
    inMemorySigningIdentity = {
      privateKey: generated.privateKey,
      publicKey: generated.publicKey,
      publicKeyB64u: generated.publicKeyB64u,
      keyId: generated.keyId,
    };
    return inMemorySigningIdentity;
  }
}

export async function encryptForDeviceStorage(
  aadContext: string,
  value: unknown
): Promise<string> {
  const { aesKey } = await getOrCreateDeviceKeys();
  const blob = await encryptOfflineQueueBlob(value, { aesKey }, aadContext);
  return JSON.stringify({ v: 'TAI-ENC-CACHE-V1', ...blob });
}

export async function decryptFromDeviceStorage<T>(
  aadContext: string,
  raw: string
): Promise<T | null> {
  try {
    const parsed = JSON.parse(raw) as { v?: string; iv?: string; ct?: string };
    if (!parsed || parsed.v !== 'TAI-ENC-CACHE-V1' || !parsed.iv || !parsed.ct) {
      return null;
    }
    const { aesKey } = await getOrCreateDeviceKeys();
    return await decryptOfflineQueueBlob<T>(
      { iv: parsed.iv, ct: parsed.ct },
      { aesKey },
      aadContext
    );
  } catch {
    return null;
  }
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

function hexToBytes(hex: string): Uint8Array {
  const clean = hex.trim();
  if (clean.length % 2 !== 0) throw new Error('Hex inválido');
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

export interface LocalCvvSealInput {
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
  capturedOffline: boolean;
  deviceId: string;
  receiverSignatureMeta?: {
    receiverUid: string;
    receiverKeyId: string;
    receiverSignature: string;
    acceptanceHash: string;
    acceptanceCryptoId: string;
  };
}

export interface LocalCvvSealOutput {
  ciphertext: string;
  iv: string;
  authTag: string;
  csgSeal: string;
  algorithm: string;
}

export async function sealCvvLocally(input: LocalCvvSealInput): Promise<LocalCvvSealOutput> {
  const { aesKey, hmacKey } = await getOrCreateDeviceKeys();

  const payload = {
    v: 'TAI-CVV-DEVICE-1',
    packageId: input.packageId.slice(0, 64),
    eventId: input.eventId.slice(0, 128),
    eventType: input.eventType,
    delivererName: input.delivererName.slice(0, 120),
    receiverName: input.receiverName.slice(0, 120),
    zone: input.zone.slice(0, 120),
    functionRole: input.functionRole.slice(0, 120),
    acceptanceNonce: input.acceptanceNonce.slice(0, 128),
    localTimestamp: input.localTimestamp.slice(0, 64),
    observations: input.observations.slice(0, 500),
    capturedOffline: input.capturedOffline,
    deviceId: input.deviceId,
    ...(input.receiverSignatureMeta
      ? {
          receiverUid: input.receiverSignatureMeta.receiverUid.slice(0, 128),
          receiverKeyId: input.receiverSignatureMeta.receiverKeyId.slice(0, 64),
          receiverSignature: input.receiverSignatureMeta.receiverSignature.slice(0, 256),
          acceptanceHash: input.receiverSignatureMeta.acceptanceHash.slice(0, 128),
          acceptanceCryptoId: input.receiverSignatureMeta.acceptanceCryptoId.slice(0, 160),
        }
      : {}),
  };

  const encoder = new TextEncoder();
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const aad = encoder.encode(`${payload.packageId}:${payload.eventId}`);
  const plaintext = encoder.encode(JSON.stringify(payload));

  const encryptedBuf = await crypto.subtle.encrypt(
    {
      name: 'AES-GCM',
      iv,
      additionalData: aad,
      tagLength: 128,
    },
    aesKey,
    plaintext
  );

  const encryptedBytes = new Uint8Array(encryptedBuf);
  const tagStart = encryptedBytes.length - 16;
  const ciphertextBytes = encryptedBytes.slice(0, tagStart);
  const authTagBytes = encryptedBytes.slice(tagStart);

  const ciphertextHex = bytesToHex(ciphertextBytes);
  const ivHex = bytesToHex(iv);
  const authTagHex = bytesToHex(authTagBytes);

  const canonical = [
    payload.packageId,
    payload.eventId,
    payload.eventType,
    payload.acceptanceNonce,
    authTagHex,
  ].join('|');

  const sigBuf = await crypto.subtle.sign('HMAC', hmacKey, encoder.encode(canonical));
  const csgSeal = bytesToHex(new Uint8Array(sigBuf));

  return {
    ciphertext: ciphertextHex,
    iv: ivHex,
    authTag: authTagHex,
    csgSeal,
    algorithm: 'WebCrypto AES-256-GCM + CSG-HMAC-SHA256 (On-Device)',
  };
}

export async function verifyCvvLocally(params: {
  ciphertext: string;
  iv: string;
  authTag: string;
  csgSeal: string;
  packageId: string;
  eventId: string;
  eventType: string;
  acceptanceNonce: string;
}): Promise<{
  valid: boolean;
  csgStatus: 'VERIFIED' | 'INVALIDATED_TAMPERED' | 'OUT_OF_FLOW';
  reason: string;
  decryptedPayload?: Record<string, unknown>;
}> {
  try {
    const { aesKey, hmacKey } = await getOrCreateDeviceKeys();
    const encoder = new TextEncoder();

    const canonical = [
      params.packageId,
      params.eventId,
      params.eventType,
      params.acceptanceNonce,
      params.authTag,
    ].join('|');

    const sealBytes = hexToBytes(params.csgSeal);
    const sealValid = await crypto.subtle.verify(
      'HMAC',
      hmacKey,
      sealBytes.buffer as ArrayBuffer,
      encoder.encode(canonical)
    );

    if (!sealValid) {
      return {
        valid: false,
        csgStatus: 'OUT_OF_FLOW',
        reason:
          'El sello CSG local no coincide con el flujo o dispositivo autorizado. Documento invalidado; registro maestro preservado.',
      };
    }

    const ciphertextBytes = hexToBytes(params.ciphertext);
    const authTagBytes = hexToBytes(params.authTag);
    const combined = new Uint8Array(ciphertextBytes.length + authTagBytes.length);
    combined.set(ciphertextBytes, 0);
    combined.set(authTagBytes, ciphertextBytes.length);

    const ivBytes = hexToBytes(params.iv);
    const aad = encoder.encode(`${params.packageId}:${params.eventId}`);

    const decryptedBuf = await crypto.subtle.decrypt(
      {
        name: 'AES-GCM',
        iv: ivBytes.buffer as ArrayBuffer,
        additionalData: aad,
        tagLength: 128,
      },
      aesKey,
      combined
    );

    const parsed = JSON.parse(new TextDecoder().decode(decryptedBuf)) as Record<string, unknown>;
    return {
      valid: true,
      csgStatus: 'VERIFIED',
      decryptedPayload: parsed,
      reason: 'Integridad AES-256-GCM y sello CSG verificados en el dispositivo.',
    };
  } catch {
    return {
      valid: false,
      csgStatus: 'INVALIDATED_TAMPERED',
      reason:
        'Fallo de autenticación AES-256-GCM en el dispositivo (AuthTag o ciphertext alterado). CSG invalida el documento.',
    };
  }
}
