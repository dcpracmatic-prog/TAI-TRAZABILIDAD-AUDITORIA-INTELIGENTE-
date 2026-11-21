import assert from 'node:assert/strict';
import test from 'node:test';
import {
  ACTIVE_CSG_PROVIDER,
  buildOfflineCryptoBrowserRuntime,
  decryptOfflineQueueBlob,
  encryptOfflineQueueBlob,
  generateEcdsaIdentityKeyPair,
  generateOfflineEventId,
  generateOfflineNonce,
  generateOfflineSessionKeys,
  parseAndVerifyAcceptanceQr,
  sealTransferEventOffline,
  signAcceptanceQrPayload,
  signCrossStationEvent,
  unlockOfflineCredentialVault,
  verifyCrossStationEventProof,
  verifyTransferEventOffline,
} from '../src/lib/offlineCrypto';
import { generateProtectedOfflineHtml } from '../src/lib/offlineHtmlExporter';
import {
  evaluateTransferIdempotency,
  syncOfflineQueueBatch,
  verifyImportedOfflineBatch,
  type ImportedBatchPayload,
} from '../src/lib/offlineSyncEngine';
import type { OfflinePendingEvent, TaiPackage, TraceEvent } from '../src/types/tai';

const SAMPLE_PACKAGE: TaiPackage = {
  id: 'PKG_YPF_01',
  code: 'TAI-BA-2025-001',
  ownerId: 'uid-supervisor-01',
  ownerEmail: 'supervisor@ypf-piloto.local',
  fromArea: 'Almacén Central Dock Sud',
  targetArea: 'Planta Compresores Sur',
  zone: 'Zona Operativa Sur · Dock Sud',
  contentSummary: 'Kit válvulas de seguridad 4 pulgadas',
  quantity: 6,
  unit: 'piezas',
  identificationStatus: 'verified',
  sealStatus: 'intact',
  lifecycleStatus: 'packed',
  qrPayload: 'tai://pkg|PKG_YPF_01|TAI-BA-2025-001',
  observations: 'Unidad piloto verificada',
  cvvId: 'CVV_INIT_01',
  eventCount: 1,
  createdAt: '2025-01-10T10:00:00.000Z',
  updatedAt: '2025-01-10T10:00:00.000Z',
};

test('1. Verifiable receiver identity in Acceptance QR (ECDSA P-256) rejects tampered/unsigned QRs', async () => {
  const receiverIdentity = await generateEcdsaIdentityKeyPair(false);
  const nonce = generateOfflineNonce();

  const signed = await signAcceptanceQrPayload(
    {
      packageId: SAMPLE_PACKAGE.id,
      eventType: 'receive',
      nonce,
      receiverName: 'Ing. Laura Méndez',
      zone: SAMPLE_PACKAGE.zone,
      receiverUid: 'uid-receiver-laura',
      receiverDeviceId: 'PHONE_REC_09',
    },
    receiverIdentity
  );

  // Legitimate scan on deliverer device
  const verified = await parseAndVerifyAcceptanceQr(signed.qrString);
  assert.equal(verified.valid, true);
  assert.ok(verified.parsed);
  assert.equal(signed.qrString.split('|').length, 13);
  assert.match(signed.acceptanceHash, /^[0-9a-f]{64}$/);
  assert.equal(
    signed.acceptanceCryptoId,
    `${nonce}:${signed.acceptanceHash.slice(0, 16).toUpperCase()}`
  );
  assert.equal(verified.parsed.acceptanceHash, signed.acceptanceHash);
  assert.equal(verified.parsed.acceptanceCryptoId, signed.acceptanceCryptoId);
  assert.equal(verified.parsed.proof.acceptanceHash, signed.acceptanceHash);
  assert.equal(verified.parsed.proof.acceptanceCryptoId, signed.acceptanceCryptoId);
  assert.equal(verified.parsed.receiverUid, 'uid-receiver-laura');
  assert.equal(verified.parsed.receiverDeviceId, 'PHONE_REC_09');
  assert.equal(verified.parsed.proof.receiverKeyId, receiverIdentity.keyId);

  // Tamper acceptanceHash without resigning -> rejected
  const tamperedHash = signed.qrString.replace(
    signed.acceptanceHash,
    '0'.repeat(64)
  );
  const rejectedHashTamper = await parseAndVerifyAcceptanceQr(tamperedHash);
  assert.equal(rejectedHashTamper.valid, false);

  // Tamper receiverUid without resigning -> rejected
  const tamperedUid = signed.qrString.replace('uid-receiver-laura', 'uid-attacker-99');
  const rejectedTamper = await parseAndVerifyAcceptanceQr(tamperedUid);
  assert.equal(rejectedTamper.valid, false);

  // Legacy 12-part QR without nonce+hash segment -> rejected
  const withoutHash = signed.qrString.split('|').slice(0, 12).join('|');
  const rejectedNoHash = await parseAndVerifyAcceptanceQr(withoutHash);
  assert.equal(rejectedNoHash.valid, false);

  // Legacy unsigned 7-part QR -> rejected
  const legacyUnsigned = `tai://accept|${SAMPLE_PACKAGE.id}|receive|${nonce}|Ing. Laura Méndez|Zona Sur`;
  const rejectedUnsigned = await parseAndVerifyAcceptanceQr(legacyUnsigned);
  assert.equal(rejectedUnsigned.valid, false);

  // Expired QR (> 24h) -> rejected
  const expiredCheck = await parseAndVerifyAcceptanceQr(signed.qrString, {
    nowMs: Date.now() + 26 * 60 * 60 * 1000,
  });
  assert.equal(expiredCheck.valid, false);
});

test('2. Offline HTML station generation, vault unlock, offline CVV sealing, and cross-station verification', async () => {
  const platformIssuer = await generateEcdsaIdentityKeyPair(false);
  const receiverDevice = await generateEcdsaIdentityKeyPair(false);
  const passphrase = 'YpfOffline#2025!';

  // Export standalone HTML station certified by platform issuer
  const exported = await generateProtectedOfflineHtml({
    passphrase,
    user: {
      uid: 'uid-deliverer-carlos',
      email: 'carlos.entrega@ypf-piloto.local',
      displayName: 'Carlos Entrega',
    },
    deviceId: 'TABLET_BA_04',
    packages: [SAMPLE_PACKAGE],
    events: [],
    offlineQueue: [],
    pilotConfig: null,
    issuerSigner: platformIssuer,
  });

  // Extract embedded JSON bundle from HTML
  const match = exported.html.match(
    /<script id="tai-offline-bundle" type="application\/json">([\s\S]*?)<\/script>/
  );
  assert.ok(match, 'HTML debe incluir el bloque JSON cifrado tai-offline-bundle');
  const bundle = JSON.parse(match[1]) as { vault: Parameters<typeof unlockOfflineCredentialVault>[0] };

  // Wrong passphrase fails AES-256-GCM decryption
  await assert.rejects(
    () => unlockOfflineCredentialVault(bundle.vault, 'WrongPassphrase!'),
    /OperationError|authenticate|decrypt|Error/i
  );

  // Correct passphrase unlocks session + ECDSA P-256 station identity
  const unlocked = await unlockOfflineCredentialVault(bundle.vault, passphrase);
  assert.equal(unlocked.operator.uid, 'uid-deliverer-carlos');
  assert.equal(unlocked.ecdsa.keyId, exported.stationIdentity.keyId);
  assert.ok(unlocked.ecdsa.stationCert);

  // Receiver device generates signed acceptance QR
  const acceptQr = await signAcceptanceQrPayload(
    {
      packageId: SAMPLE_PACKAGE.id,
      eventType: 'receive',
      nonce: generateOfflineNonce(),
      receiverName: 'Recepción Dock Sud',
      zone: SAMPLE_PACKAGE.zone,
      receiverUid: 'uid-receiver-dock',
      receiverDeviceId: 'PHONE_DOCK_02',
    },
    receiverDevice
  );
  const scanned = await parseAndVerifyAcceptanceQr(acceptQr.qrString);
  assert.equal(scanned.valid, true);
  assert.ok(scanned.parsed);

  // Offline station seals CVV using its own symmetric keys + signs cross-station proof with ECDSA
  const localTimestamp = new Date().toISOString();
  const sealed = await sealTransferEventOffline(
    {
      packageId: SAMPLE_PACKAGE.id,
      eventId: generateOfflineEventId('CVV_HTML'),
      eventType: scanned.parsed.eventType,
      delivererName: unlocked.operator.displayName,
      receiverName: scanned.parsed.receiverName,
      zone: scanned.parsed.zone,
      functionRole: 'Operador Offline',
      acceptanceNonce: scanned.parsed.nonce,
      localTimestamp,
      observations: 'Entrega sin cobertura celular en Dock Sud.',
      deviceId: unlocked.deviceId,
      operatorUid: unlocked.operator.uid,
      operatorEmail: unlocked.operator.email,
      acceptanceProof: scanned.parsed.proof,
    },
    unlocked.keys
  );

  // Local symmetric verification on the offline station passes
  const localVerify = await verifyTransferEventOffline(
    {
      ciphertext: sealed.ciphertext,
      iv: sealed.iv,
      authTag: sealed.authTag,
      csgSeal: sealed.csgSeal,
      packageId: SAMPLE_PACKAGE.id,
      eventId: sealed.eventId,
      eventType: scanned.parsed.eventType,
      acceptanceNonce: scanned.parsed.nonce,
    },
    unlocked.keys
  );
  assert.equal(localVerify.valid, true);
  assert.equal(localVerify.decryptedPayload?.receiverSignature, scanned.parsed.proof.signatureB64u);
  assert.equal(localVerify.decryptedPayload?.acceptanceHash, scanned.parsed.acceptanceHash);
  assert.equal(localVerify.decryptedPayload?.acceptanceCryptoId, scanned.parsed.acceptanceCryptoId);

  const proof = await signCrossStationEvent(
    {
      packageId: SAMPLE_PACKAGE.id,
      eventId: sealed.eventId,
      eventType: scanned.parsed.eventType,
      acceptanceNonce: scanned.parsed.nonce,
      cvvCiphertext: sealed.ciphertext,
      cvvIv: sealed.iv,
      cvvAuthTag: sealed.authTag,
      localTimestamp,
      deviceId: unlocked.deviceId,
      operatorUid: unlocked.operator.uid,
      operatorEmail: unlocked.operator.email,
      acceptanceProof: scanned.parsed.proof,
      stationCert: unlocked.ecdsa.stationCert,
    },
    {
      privateKey: unlocked.ecdsa.privateKey,
      publicKeyB64u: unlocked.ecdsa.publicKeyB64u,
      keyId: unlocked.ecdsa.keyId,
    }
  );

  const pendingEvent: OfflinePendingEvent = {
    localId: 'LOC_TEST_1',
    eventId: sealed.eventId,
    packageId: SAMPLE_PACKAGE.id,
    packageCode: SAMPLE_PACKAGE.code,
    eventType: scanned.parsed.eventType,
    delivererName: unlocked.operator.displayName,
    receiverName: scanned.parsed.receiverName,
    zone: scanned.parsed.zone,
    functionRole: 'Operador Offline',
    observations: 'Entrega sin cobertura celular en Dock Sud.',
    acceptanceNonce: scanned.parsed.nonce,
    offlineSequence: 1,
    deviceId: unlocked.deviceId,
    localTimestamp,
    sealStatus: 'intact',
    discrepancyNote: '',
    cvvCiphertext: sealed.ciphertext,
    cvvIv: sealed.iv,
    cvvAuthTag: sealed.authTag,
    csgSeal: sealed.csgSeal,
    proof,
  };

  // Second station (completely different AES/HMAC keys) imports & verifies batch cryptographically
  const batchPayload: ImportedBatchPayload = {
    format: 'tai-offline-batch-v1',
    exportedAt: new Date().toISOString(),
    operatorUid: unlocked.operator.uid,
    operatorEmail: unlocked.operator.email,
    deviceId: unlocked.deviceId,
    stationKeyId: unlocked.ecdsa.keyId,
    stationPublicKeyB64u: unlocked.ecdsa.publicKeyB64u,
    stationCert: unlocked.ecdsa.stationCert,
    events: [pendingEvent],
  };

  const verifiedBatch = await verifyImportedOfflineBatch(batchPayload, {
    trustedIssuerKeyIds: [platformIssuer.keyId],
    requireStationCert: true,
  });
  assert.equal(verifiedBatch.validEvents.length, 1);
  assert.equal(verifiedBatch.rejectedEvents.length, 0);
  assert.equal(verifiedBatch.validEvents[0].receiverSignature, scanned.parsed.proof.signatureB64u);
  assert.equal(verifiedBatch.validEvents[0].receiverKeyId, scanned.parsed.proof.receiverKeyId);
  assert.equal(verifiedBatch.validEvents[0].acceptanceHash, scanned.parsed.acceptanceHash);
  assert.equal(verifiedBatch.validEvents[0].acceptanceCryptoId, scanned.parsed.acceptanceCryptoId);

  // Tamper ciphertext in imported batch -> rejected across stations
  const tamperedBatch: ImportedBatchPayload = {
    ...batchPayload,
    events: [
      {
        ...pendingEvent,
        cvvCiphertext: pendingEvent.cvvCiphertext.slice(0, -4) + 'abcd',
      },
    ],
  };
  const rejectedTamperedBatch = await verifyImportedOfflineBatch(tamperedBatch, {
    trustedIssuerKeyIds: [platformIssuer.keyId],
    requireStationCert: true,
  });
  assert.equal(rejectedTamperedBatch.validEvents.length, 0);
  assert.equal(rejectedTamperedBatch.rejectedEvents.length, 1);

  // Forged batch claiming a different untrusted issuer -> rejected when trustedIssuerKeyIds enforced
  const untrustedIssuerCheck = await verifyCrossStationEventProof(pendingEvent, proof, {
    trustedIssuerKeyIds: ['OTHER_KEY_ID'],
    requireStationCert: true,
  });
  assert.equal(untrustedIssuerCheck.valid, false);
});

test('3. Encrypted offline queue and package snapshot protect metadata and survive offline restart', async () => {
  const deviceAesKeys = await generateOfflineSessionKeys(false);
  const sensitiveObservation = 'Inspección confidencial compresor C-12';

  const queueItems: OfflinePendingEvent[] = [
    {
      localId: 'LOC_ENC_1',
      eventId: 'CVV_OFF_ENC_1',
      packageId: SAMPLE_PACKAGE.id,
      packageCode: SAMPLE_PACKAGE.code,
      eventType: 'dispatch',
      delivererName: 'Juan Chofer',
      receiverName: 'Base Neuquén',
      zone: 'Zona Norte',
      functionRole: 'Transportista',
      observations: sensitiveObservation,
      acceptanceNonce: 'ACC_ENC_NONCE_1',
      offlineSequence: 1,
      deviceId: 'DEV_01',
      localTimestamp: '2025-01-10T11:00:00.000Z',
      sealStatus: 'intact',
      discrepancyNote: '',
      cvvCiphertext: 'aabbccdd',
      cvvIv: '00112233445566778899aabb',
      cvvAuthTag: '11223344556677889900aabbccddeeff',
      csgSeal: 'deadbeef'.repeat(8),
    },
  ];

  const snapshot = {
    packages: [SAMPLE_PACKAGE],
    knownNonces: ['ACC_ALREADY_COMMITTED_01'],
    updatedAt: '2025-01-10T11:05:00.000Z',
  };

  const encQueue = await encryptOfflineQueueBlob(queueItems, deviceAesKeys, 'tai-queue-v1:uid-1');
  const encSnapshot = await encryptOfflineQueueBlob(snapshot, deviceAesKeys, 'tai-snapshot-v1:uid-1');

  // Verify zero plaintext leakage in persisted blobs
  assert.equal(JSON.stringify(encQueue).includes(SAMPLE_PACKAGE.code), false);
  assert.equal(JSON.stringify(encQueue).includes(sensitiveObservation), false);
  assert.equal(JSON.stringify(encQueue).includes('Juan Chofer'), false);
  assert.equal(JSON.stringify(encSnapshot).includes(SAMPLE_PACKAGE.code), false);
  assert.equal(JSON.stringify(encSnapshot).includes('ACC_ALREADY_COMMITTED_01'), false);

  // Simulate offline app restart: decrypt queue and package snapshot cleanly without network
  const restoredQueue = await decryptOfflineQueueBlob<OfflinePendingEvent[]>(
    encQueue,
    deviceAesKeys,
    'tai-queue-v1:uid-1'
  );
  const restoredSnapshot = await decryptOfflineQueueBlob<typeof snapshot>(
    encSnapshot,
    deviceAesKeys,
    'tai-snapshot-v1:uid-1'
  );

  assert.equal(restoredQueue.length, 1);
  assert.equal(restoredQueue[0].observations, sensitiveObservation);
  assert.equal(restoredSnapshot.packages[0].id, SAMPLE_PACKAGE.id);
  assert.deepEqual(restoredSnapshot.knownNonces, ['ACC_ALREADY_COMMITTED_01']);
});

test('4. Partial sync failure preserves only unconfirmed events & idempotent retry avoids false conflicts', async () => {
  const makeQueueItem = (idx: number): OfflinePendingEvent => ({
    localId: `LOC_${idx}`,
    eventId: `CVV_BATCH_${idx}`,
    packageId: SAMPLE_PACKAGE.id,
    packageCode: SAMPLE_PACKAGE.code,
    eventType: 'receive',
    delivererName: 'Entrega 1',
    receiverName: 'Receptor 1',
    zone: SAMPLE_PACKAGE.zone,
    functionRole: 'Operador',
    observations: `Evento ${idx}`,
    acceptanceNonce: `ACC_BATCH_${idx}`,
    offlineSequence: idx,
    deviceId: 'DEV_01',
    localTimestamp: `2025-01-10T12:0${idx}:00.000Z`,
    sealStatus: 'intact',
    discrepancyNote: '',
    cvvCiphertext: 'aa'.repeat(16),
    cvvIv: 'bb'.repeat(12),
    cvvAuthTag: 'cc'.repeat(16),
    csgSeal: `${idx}`.repeat(64).slice(0, 64),
  });

  const q1 = makeQueueItem(1);
  const q2 = makeQueueItem(2);
  const q3 = makeQueueItem(3);

  const serverCommitted: TraceEvent[] = [];
  const queueSnapshots: string[][] = [];
  let failSecondOnce = true;

  const firstRun = await syncOfflineQueueBatch({
    queue: [q1, q2, q3],
    packages: [SAMPLE_PACKAGE],
    uploadItem: async (item) => {
      const decision = evaluateTransferIdempotency({
        existingEvents: serverCommitted,
        acceptanceNonce: item.acceptanceNonce,
        capturedOffline: true,
        offlineSequence: item.offlineSequence,
        preSealed: { eventId: item.eventId, csgSeal: item.csgSeal },
      });
      if (decision.status === 'already_synced') {
        return { duplicateOrConflict: false, alreadySynced: true };
      }
      if (decision.status !== 'new_valid') {
        return { duplicateOrConflict: true, reason: decision.reason };
      }
      if (item.eventId === q2.eventId && failSecondOnce) {
        failSecondOnce = false;
        throw new Error('Timeout de red simulado en evento #2');
      }
      serverCommitted.push({
        id: item.eventId,
        packageId: item.packageId,
        ownerId: 'uid-1',
        eventType: item.eventType,
        delivererName: item.delivererName,
        receiverName: item.receiverName,
        zone: item.zone,
        functionRole: item.functionRole,
        observations: item.observations,
        acceptanceNonce: item.acceptanceNonce,
        capturedOffline: true,
        offlineSequence: item.offlineSequence,
        localTimestamp: item.localTimestamp,
        discrepancyNote: item.discrepancyNote,
        cvvCiphertext: item.cvvCiphertext,
        cvvIv: item.cvvIv,
        cvvAuthTag: item.cvvAuthTag,
        csgSeal: item.csgSeal,
        cvvState: 'valid',
      });
      return { duplicateOrConflict: false };
    },
    onQueueProgress: (next) => {
      queueSnapshots.push(next.map((n) => n.eventId));
    },
  });

  // Item 1 synced and was immediately removed; item 2 failed transiently and item 3 stayed in order
  assert.equal(firstRun.synced, 1);
  assert.equal(firstRun.failed, 1);
  assert.equal(firstRun.conflicts, 0);
  assert.deepEqual(
    firstRun.remaining.map((r) => r.eventId),
    [q2.eventId, q3.eventId]
  );
  assert.equal(firstRun.remaining[0].retryCount, 1);
  assert.match(firstRun.remaining[0].lastSyncError || '', /Timeout de red/);
  // Per-event persistence verified: after q1 succeeded, q1 was removed before q2 failed
  assert.deepEqual(queueSnapshots[0], [q2.eventId, q3.eventId]);

  // Verify idempotency classifier handles explicit retry of q1 without creating a false conflict
  const retryQ1 = evaluateTransferIdempotency({
    existingEvents: serverCommitted,
    acceptanceNonce: q1.acceptanceNonce,
    capturedOffline: true,
    offlineSequence: q1.offlineSequence,
    preSealed: { eventId: q1.eventId, csgSeal: q1.csgSeal },
  });
  assert.equal(retryQ1.status, 'already_synced');

  // Genuine QR replay (same nonce, different eventId & different csgSeal) STILL flagged as conflict
  const genuineReplay = evaluateTransferIdempotency({
    existingEvents: serverCommitted,
    acceptanceNonce: q1.acceptanceNonce,
    capturedOffline: true,
    offlineSequence: 4,
    preSealed: { eventId: 'CVV_FORGED_REPLAY', csgSeal: 'f'.repeat(64) },
  });
  assert.equal(genuineReplay.status, 'duplicate_qr_conflict');

  // Second run syncs remaining q2 cleanly with 0 conflicts
  const secondRun = await syncOfflineQueueBatch({
    queue: firstRun.remaining,
    packages: [SAMPLE_PACKAGE],
    uploadItem: async (item) => {
      const decision = evaluateTransferIdempotency({
        existingEvents: serverCommitted,
        acceptanceNonce: item.acceptanceNonce,
        capturedOffline: true,
        offlineSequence: item.offlineSequence,
        preSealed: { eventId: item.eventId, csgSeal: item.csgSeal },
      });
      if (decision.status === 'already_synced') {
        return { duplicateOrConflict: false, alreadySynced: true };
      }
      if (decision.status !== 'new_valid') {
        return { duplicateOrConflict: true, reason: decision.reason };
      }
      serverCommitted.push({
        id: item.eventId,
        packageId: item.packageId,
        ownerId: 'uid-1',
        eventType: item.eventType,
        delivererName: item.delivererName,
        receiverName: item.receiverName,
        zone: item.zone,
        functionRole: item.functionRole,
        observations: item.observations,
        acceptanceNonce: item.acceptanceNonce,
        capturedOffline: true,
        offlineSequence: item.offlineSequence,
        localTimestamp: item.localTimestamp,
        discrepancyNote: item.discrepancyNote,
        cvvCiphertext: item.cvvCiphertext,
        cvvIv: item.cvvIv,
        cvvAuthTag: item.cvvAuthTag,
        csgSeal: item.csgSeal,
        cvvState: 'valid',
      });
      return { duplicateOrConflict: false };
    },
    onQueueProgress: () => {},
  });

  assert.equal(secondRun.synced, 2);
  assert.equal(secondRun.failed, 0);
  assert.equal(secondRun.conflicts, 0);
  assert.equal(secondRun.remaining.length, 0);
});

test('5. CSG provider disclosure is transparent and HTML runtime escapes script closing tags', () => {
  assert.equal(ACTIVE_CSG_PROVIDER.providerId, 'webcrypto-ecdsa-p256-hmac-v1');
  assert.equal(ACTIVE_CSG_PROVIDER.usesRustSelloIntegridad, false);
  assert.match(ACTIVE_CSG_PROVIDER.displayName, /sello_integridad/i);

  const runtimeScript = buildOfflineCryptoBrowserRuntime();
  assert.equal(/<\/script/i.test(runtimeScript), false);
});
