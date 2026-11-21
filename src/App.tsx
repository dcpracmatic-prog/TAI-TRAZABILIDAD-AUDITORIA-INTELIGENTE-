import { useCallback, useEffect, useRef, useState } from 'react';
import type { User } from 'firebase/auth';
import { LogOut, Wifi, WifiOff } from 'lucide-react';
import { CsgAuditSection } from './components/CsgAuditSection';
import { ErrorBoundary } from './components/ErrorBoundary';
import { LogisticsHubSection } from './components/LogisticsHubSection';
import { OverviewSection } from './components/OverviewSection';
import { PackagingSection } from './components/PackagingSection';
import { TransfersSection } from './components/TransfersSection';
import { googleSignIn, initAuth, logout } from './lib/firebase';
import { syncOfflineQueueBatch } from './lib/offlineSyncEngine';
import {
  createPackageWithPackEvent,
  invalidateCvvByCsg,
  loadPilotBaselineScenario,
  loadPilotConfig,
  logSheetsSyncAudit,
  readAllEventProofsFromDevice,
  readEncryptedOfflineQueue,
  readEncryptedOfflineSnapshot,
  readTrustedStationKeys,
  recordTransferEvent,
  registerTrustedStationKey,
  saveEventProofsToDevice,
  savePilotConfig,
  subscribeAuditLogs,
  subscribePackageEvents,
  subscribeUserPackages,
  validateUncertainMaterial,
  writeEncryptedOfflineQueue,
  writeEncryptedOfflineSnapshot,
} from './lib/taiService';
import type {
  AuditLog,
  CrossStationEventProof,
  IdentificationStatus,
  OfflinePendingEvent,
  PilotConfig,
  SealStatus,
  TaiPackage,
  TraceEvent,
  TraceEventType,
} from './types/tai';

type NavTab = 'overview' | 'packaging' | 'transfers' | 'audit' | 'hub';

const NAV_ITEMS: Array<{ id: NavTab; label: string }> = [
  { id: 'overview', label: 'Resumen' },
  { id: 'packaging', label: 'Embalaje y QR' },
  { id: 'transfers', label: 'Transferencias' },
  { id: 'audit', label: 'Auditoría CSG' },
  { id: 'hub', label: 'Centro Logístico' },
];

function GoogleSignInButton({
  onClick,
  loading,
}: {
  onClick: () => void;
  loading: boolean;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      disabled={loading}
      className="inline-flex items-center gap-2 rounded-lg border border-slate-300 bg-white px-3.5 py-2 text-xs font-semibold text-slate-800 shadow-xs transition-colors hover:bg-slate-50 disabled:opacity-50 whitespace-nowrap shrink-0"
    >
      <svg
        xmlns="http://www.w3.org/2000/svg"
        viewBox="0 0 48 48"
        className="h-4 w-4 shrink-0"
        aria-hidden="true"
      >
        <path
          fill="#EA4335"
          d="M24 9.5c3.54 0 6.71 1.22 9.21 3.6l6.85-6.85C35.9 2.38 30.47 0 24 0 14.62 0 6.51 5.38 2.56 13.22l7.98 6.19C12.43 13.72 17.74 9.5 24 9.5z"
        />
        <path
          fill="#4285F4"
          d="M46.98 24.55c0-1.57-.15-3.09-.38-4.55H24v9.02h12.94c-.58 2.96-2.26 5.48-4.78 7.18l7.73 6c4.51-4.18 7.09-10.36 7.09-17.65z"
        />
        <path
          fill="#FBBC05"
          d="M10.53 28.59c-.48-1.45-.76-2.99-.76-4.59s.27-3.14.76-4.59l-7.98-6.19C.92 16.46 0 20.12 0 24c0 3.88.92 7.54 2.56 10.78l7.97-6.19z"
        />
        <path
          fill="#34A853"
          d="M24 48c6.48 0 11.93-2.13 15.89-5.81l-7.73-6c-2.15 1.45-4.92 2.3-8.16 2.3-6.26 0-11.57-4.22-13.47-9.91l-7.98 6.19C6.51 42.62 14.62 48 24 48z"
        />
      </svg>
      <span>{loading ? 'Conectando...' : 'Sign in with Google'}</span>
    </button>
  );
}

function TaiWorkspace() {
  const [activeTab, setActiveTab] = useState<NavTab>('overview');
  const [user, setUser] = useState<User | null>(null);
  const [accessToken, setAccessToken] = useState<string | null>(null);
  const [authReady, setAuthReady] = useState(false);
  const [authLoading, setAuthLoading] = useState(false);

  const [packages, setPackages] = useState<TaiPackage[]>([]);
  const [selectedPackageId, setSelectedPackageId] = useState<string | null>(null);
  const [events, setEvents] = useState<TraceEvent[]>([]);
  const [auditLogs, setAuditLogs] = useState<AuditLog[]>([]);
  const [pilotConfig, setPilotConfig] = useState<PilotConfig | null>(null);

  const [simulatedOffline, setSimulatedOffline] = useState(false);
  const [networkOnline, setNetworkOnline] = useState(() =>
    typeof navigator !== 'undefined' ? navigator.onLine : true
  );
  const [autoSyncOnReconnect, setAutoSyncOnReconnect] = useState(true);
  const [offlineQueue, setOfflineQueue] = useState<OfflinePendingEvent[]>([]);
  const [cachedKnownNonces, setCachedKnownNonces] = useState<string[]>([]);
  const [trustedStationKeys, setTrustedStationKeys] = useState<string[]>([]);
  const [eventProofs, setEventProofs] = useState<Record<string, CrossStationEventProof>>({});
  const [isBusy, setIsBusy] = useState(false);
  const [statusMessage, setStatusMessage] = useState('');
  const [errorBanner, setErrorBanner] = useState('');

  const effectiveOffline = simulatedOffline || !networkOnline;
  const syncingRef = useRef(false);

  useEffect(() => {
    const onOnline = () => setNetworkOnline(true);
    const onOffline = () => setNetworkOnline(false);
    window.addEventListener('online', onOnline);
    window.addEventListener('offline', onOffline);
    return () => {
      window.removeEventListener('online', onOnline);
      window.removeEventListener('offline', onOffline);
    };
  }, []);

  useEffect(() => {
    const unsub = initAuth((nextUser, token) => {
      setUser(nextUser);
      setAccessToken(token);
      setAuthReady(true);
    });
    return () => unsub();
  }, []);

  useEffect(() => {
    if (!user) {
      setPackages([]);
      setEvents([]);
      setAuditLogs([]);
      setPilotConfig(null);
      setOfflineQueue([]);
      setCachedKnownNonces([]);
      setTrustedStationKeys([]);
      setEventProofs({});
      return;
    }

    let cancelled = false;
    void (async () => {
      const [queue, snapshot, proofs, stations] = await Promise.all([
        readEncryptedOfflineQueue(user.uid),
        readEncryptedOfflineSnapshot(user.uid),
        readAllEventProofsFromDevice(user.uid),
        readTrustedStationKeys(user.uid),
      ]);
      if (cancelled) return;
      setOfflineQueue(queue);
      setEventProofs(proofs);
      setTrustedStationKeys(stations);
      if (snapshot) {
        if (snapshot.packages.length > 0) {
          setPackages((prev) => (prev.length > 0 ? prev : snapshot.packages));
          setCachedKnownNonces(snapshot.knownNonces || []);
          setSelectedPackageId((prev) => prev || snapshot.packages[0]?.id || null);
        }
        if (snapshot.pilotConfig) {
          setPilotConfig((prev) => prev ?? snapshot.pilotConfig ?? null);
        }
      }
    })();

    const unsubPkgs = subscribeUserPackages(
      user.uid,
      (items) => {
        if (items.length > 0 || !effectiveOffline) {
          setPackages(items);
          setSelectedPackageId((prev) =>
            prev && items.some((p) => p.id === prev) ? prev : items[0]?.id ?? null
          );
        }
      },
      (err) => setErrorBanner(err.message)
    );

    const unsubLogs = subscribeAuditLogs(
      user.uid,
      (logs) => setAuditLogs(logs),
      (err) => setErrorBanner(err.message)
    );

    if (!effectiveOffline) {
      loadPilotConfig(user.uid)
        .then((cfg) => {
          if (cfg) setPilotConfig(cfg);
        })
        .catch((err) => {
          setErrorBanner(err instanceof Error ? err.message : String(err));
        });
    }

    return () => {
      cancelled = true;
      unsubPkgs();
      unsubLogs();
    };
  }, [user, effectiveOffline]);

  useEffect(() => {
    if (!user || (packages.length === 0 && !pilotConfig)) return;
    const mergedNonces = Array.from(
      new Set([
        ...cachedKnownNonces,
        ...events.filter((e) => e.cvvState === 'valid').map((e) => e.acceptanceNonce),
      ])
    ).slice(0, 500);
    void writeEncryptedOfflineSnapshot(user.uid, {
      packages,
      knownNonces: mergedNonces,
      pilotConfig,
      savedAt: new Date().toISOString(),
    });
  }, [user, packages, events, cachedKnownNonces, pilotConfig]);

  useEffect(() => {
    if (!user || !selectedPackageId) {
      setEvents([]);
      return;
    }
    const unsubEvents = subscribePackageEvents(
      selectedPackageId,
      user.uid,
      (evts) => setEvents(evts),
      (err) => setErrorBanner(err.message)
    );
    return () => unsubEvents();
  }, [user, selectedPackageId]);

  const selectedPackage =
    packages.find((p) => p.id === selectedPackageId) || packages[0] || null;

  async function handleLogin() {
    setAuthLoading(true);
    setErrorBanner('');
    try {
      const res = await googleSignIn();
      setUser(res.user);
      setAccessToken(res.accessToken);
    } catch (err) {
      setErrorBanner(
        err instanceof Error ? err.message : 'No se pudo completar el inicio de sesión con Google.'
      );
    } finally {
      setAuthLoading(false);
    }
  }

  async function handleLogout() {
    await logout();
    setUser(null);
    setAccessToken(null);
  }

  async function handleCreatePackage(input: {
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
  }) {
    if (!user) return;
    setIsBusy(true);
    setErrorBanner('');
    try {
      const created = await createPackageWithPackEvent({
        ownerId: user.uid,
        ownerEmail: user.email || 'operador@tai.local',
        ...input,
      });
      setSelectedPackageId(created.packageId);
      setStatusMessage(`Unidad ${input.code} empacada y sellada con CVV.`);
    } catch (err) {
      setErrorBanner(err instanceof Error ? err.message : String(err));
    } finally {
      setIsBusy(false);
    }
  }

  async function handleValidateMaterial(params: {
    pkg: TaiPackage;
    confirmedDescription: string;
    confirmedQuantity: number;
    validationNote: string;
  }) {
    if (!user) return;
    setIsBusy(true);
    try {
      await validateUncertainMaterial({
        ...params,
        ownerId: user.uid,
        ownerEmail: user.email || 'supervisor@tai.local',
      });
      setStatusMessage(`Identificación validada para ${params.pkg.code}.`);
    } catch (err) {
      setErrorBanner(err instanceof Error ? err.message : String(err));
    } finally {
      setIsBusy(false);
    }
  }

  async function handleRecordOnlineTransfer(params: {
    pkg: TaiPackage;
    eventType: TraceEventType;
    delivererName: string;
    receiverName: string;
    zone: string;
    functionRole: string;
    observations: string;
    acceptanceNonce: string;
    sealStatus: SealStatus;
    discrepancyNote: string;
    preSealed: {
      eventId: string;
      ciphertext: string;
      iv: string;
      authTag: string;
      csgSeal: string;
    };
    receiverSignatureMeta?: {
      receiverUid: string;
      receiverKeyId: string;
      receiverSignature: string;
      acceptanceHash: string;
      acceptanceCryptoId: string;
    };
    localTimestamp: string;
  }) {
    if (!user) return { duplicateOrConflict: false };
    setIsBusy(true);
    setErrorBanner('');
    try {
      const nextLifecycle =
        params.eventType === 'return'
          ? 'return_open'
          : params.eventType === 'dispatch'
            ? 'in_transit'
            : 'received';

      return await recordTransferEvent({
        ...params,
        ownerId: user.uid,
        ownerEmail: user.email || 'operador@tai.local',
        capturedOffline: false,
        offlineSequence: 0,
        nextLifecycleStatus: nextLifecycle,
      });
    } finally {
      setIsBusy(false);
    }
  }

  function handleEnqueueOfflineEvent(item: OfflinePendingEvent) {
    if (!user) return;
    const next = [...offlineQueue, item];
    setOfflineQueue(next);
    void writeEncryptedOfflineQueue(user.uid, next);
    if (item.proof) {
      const nextProofs = { ...eventProofs, [item.eventId]: item.proof };
      setEventProofs(nextProofs);
      void saveEventProofsToDevice(user.uid, { [item.eventId]: item.proof });
    }
  }

  function handleSaveEventProof(eventId: string, proof: CrossStationEventProof) {
    if (!user) return;
    setEventProofs((prev) => ({ ...prev, [eventId]: proof }));
    void saveEventProofsToDevice(user.uid, { [eventId]: proof });
  }

  async function handleRegisterTrustedStation(stationKeyId: string) {
    if (!user) return;
    const next = await registerTrustedStationKey(user.uid, stationKeyId);
    setTrustedStationKeys(next);
  }

  function handleImportOfflineBatch(items: OfflinePendingEvent[]): { added: number; skipped: number } {
    if (!user) return { added: 0, skipped: items.length };
    const existingIds = new Set(offlineQueue.map((q) => q.eventId));
    const existingNonces = new Set(offlineQueue.map((q) => q.acceptanceNonce));
    const toAdd: OfflinePendingEvent[] = [];
    const proofsToStore: Record<string, CrossStationEventProof> = {};
    let skipped = 0;

    for (const item of items) {
      if (existingIds.has(item.eventId) || existingNonces.has(item.acceptanceNonce)) {
        skipped += 1;
        continue;
      }
      existingIds.add(item.eventId);
      existingNonces.add(item.acceptanceNonce);
      toAdd.push(item);
      if (item.proof) {
        proofsToStore[item.eventId] = item.proof;
      }
    }

    if (toAdd.length > 0) {
      const next = [...offlineQueue, ...toAdd];
      setOfflineQueue(next);
      void writeEncryptedOfflineQueue(user.uid, next);
      if (Object.keys(proofsToStore).length > 0) {
        setEventProofs((prev) => ({ ...prev, ...proofsToStore }));
        void saveEventProofsToDevice(user.uid, proofsToStore);
      }
      setStatusMessage(`Importados y verificados ${toAdd.length} evento(s) CVV desde estación HTML offline.`);
    }
    return { added: toAdd.length, skipped };
  }

  const handleSyncOfflineQueue = useCallback(async () => {
    if (!user || effectiveOffline || offlineQueue.length === 0 || syncingRef.current) return;
    syncingRef.current = true;
    setIsBusy(true);
    setErrorBanner('');
    try {
      const summary = await syncOfflineQueueBatch({
        queue: offlineQueue,
        packages,
        uploadItem: async (item, pkg) => {
          const nextLifecycle =
            item.eventType === 'return'
              ? 'return_open'
              : item.eventType === 'dispatch'
                ? 'in_transit'
                : 'received';
          return recordTransferEvent({
            pkg,
            ownerId: user.uid,
            ownerEmail: user.email || 'operador@tai.local',
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
            sealStatus: item.sealStatus,
            discrepancyNote: item.discrepancyNote,
            nextLifecycleStatus: nextLifecycle,
            preSealed: {
              eventId: item.eventId,
              ciphertext: item.cvvCiphertext,
              iv: item.cvvIv,
              authTag: item.cvvAuthTag,
              csgSeal: item.csgSeal,
            },
            receiverSignatureMeta:
              item.receiverSignature || item.proof?.acceptanceProof
                ? {
                    receiverUid: item.receiverUid || item.proof?.acceptanceProof?.receiverUid || '',
                    receiverKeyId:
                      item.receiverKeyId || item.proof?.acceptanceProof?.receiverKeyId || '',
                    receiverSignature:
                      item.receiverSignature || item.proof?.acceptanceProof?.signatureB64u || '',
                    acceptanceHash:
                      item.acceptanceHash || item.proof?.acceptanceProof?.acceptanceHash || '',
                    acceptanceCryptoId:
                      item.acceptanceCryptoId ||
                      item.proof?.acceptanceProof?.acceptanceCryptoId ||
                      '',
                  }
                : undefined,
          });
        },
        onQueueProgress: async (nextQueue) => {
          setOfflineQueue(nextQueue);
          await writeEncryptedOfflineQueue(user.uid, nextQueue);
        },
      });

      if (summary.failed > 0 && summary.lastError) {
        setErrorBanner(
          `Sincronización parcial: ${summary.synced} enviado(s), ${summary.alreadySynced} ya confirmados, ${summary.failed} con error (${summary.lastError}). Los enviados ya fueron retirados de la cola.`
        );
      } else {
        setStatusMessage(
          `Sincronización offline completada: ${summary.synced} enviado(s), ${summary.alreadySynced} idempotente(s), ${summary.conflicts} conflicto(s).`
        );
      }
    } catch (err) {
      setErrorBanner(err instanceof Error ? err.message : String(err));
    } finally {
      syncingRef.current = false;
      setIsBusy(false);
    }
  }, [user, effectiveOffline, offlineQueue, packages]);

  useEffect(() => {
    if (!effectiveOffline && autoSyncOnReconnect && user && offlineQueue.length > 0 && packages.length > 0) {
      handleSyncOfflineQueue();
    }
  }, [effectiveOffline, autoSyncOnReconnect, user, offlineQueue.length, packages.length, handleSyncOfflineQueue]);

  async function handleLoadSample() {
    if (!user) return;
    setIsBusy(true);
    setErrorBanner('');
    try {
      await loadPilotBaselineScenario(user.uid, user.email || 'piloto@tai.local');
      setStatusMessage('Escenario piloto de Buenos Aires cargado con 2 unidades TAI y CVV sellado.');
    } catch (err) {
      setErrorBanner(err instanceof Error ? err.message : String(err));
    } finally {
      setIsBusy(false);
    }
  }

  return (
    <div className="min-h-screen bg-slate-50 text-slate-900">
      {/* Strict 3-Zone Top Bar Contract */}
      <header className="border-b border-slate-200 bg-white">
        <div className="mx-auto flex max-w-7xl items-center justify-between gap-8 px-6 py-4">
          {/* Zone 1: Single-line Brand Wordmark */}
          <button
            type="button"
            onClick={() => setActiveTab('overview')}
            className="font-display text-lg font-bold tracking-tight text-slate-900 whitespace-nowrap shrink-0"
          >
            TAI · Piloto YPF
          </button>

          {/* Zone 2: 5 concise single-line text nav links */}
          <nav className="hidden md:flex items-center gap-6 text-sm font-medium text-slate-600">
            {NAV_ITEMS.map((item) => (
              <button
                key={item.id}
                type="button"
                onClick={() => setActiveTab(item.id)}
                className={`transition-colors whitespace-nowrap shrink-0 pb-0.5 ${
                  activeTab === item.id
                    ? 'border-b-2 border-sky-700 font-semibold text-slate-900'
                    : 'hover:text-slate-900'
                }`}
              >
                {item.label}
              </button>
            ))}
          </nav>

          {/* Zone 3: 1 primary auth action */}
          <div className="flex items-center gap-3 shrink-0">
            {!authReady ? (
              <span className="text-xs text-slate-500 whitespace-nowrap">Cargando...</span>
            ) : user ? (
              <button
                type="button"
                onClick={handleLogout}
                className="inline-flex items-center gap-2 rounded-lg border border-slate-200 bg-white px-3.5 py-2 text-xs font-semibold text-slate-700 hover:bg-slate-50 whitespace-nowrap shrink-0"
              >
                <LogOut className="h-3.5 w-3.5" />
                Salir ({user.email?.split('@')[0]})
              </button>
            ) : (
              <GoogleSignInButton onClick={handleLogin} loading={authLoading} />
            )}
          </div>
        </div>
      </header>

      {/* Workspace Toolbar (Mode toggles & mobile nav live below header) */}
      <div className="border-b border-slate-200 bg-slate-100/70">
        <div className="mx-auto flex max-w-7xl flex-wrap items-center justify-between gap-4 px-6 py-2.5">
          <div className="flex md:hidden items-center gap-1 overflow-x-auto">
            {NAV_ITEMS.map((item) => (
              <button
                key={item.id}
                type="button"
                onClick={() => setActiveTab(item.id)}
                className={`rounded-md px-2.5 py-1 text-xs font-medium whitespace-nowrap shrink-0 ${
                  activeTab === item.id
                    ? 'bg-white text-slate-900 shadow-xs'
                    : 'text-slate-600'
                }`}
              >
                {item.label}
              </button>
            ))}
          </div>

          <div className="hidden md:flex items-center gap-2 text-xs text-slate-600">
            <span>Trazabilidad y Auditoría Inteligente</span>
            <span aria-hidden="true">·</span>
            <span>Centro Logístico Buenos Aires</span>
            {statusMessage && (
              <>
                <span aria-hidden="true">·</span>
                <span className="font-medium text-sky-800">{statusMessage}</span>
              </>
            )}
          </div>

          <div className="flex items-center gap-3">
            <button
              type="button"
              onClick={() => setSimulatedOffline((prev) => !prev)}
              className={`inline-flex items-center gap-1.5 rounded-lg border px-3 py-1.5 text-xs font-semibold transition-colors whitespace-nowrap shrink-0 ${
                effectiveOffline
                  ? 'border-amber-300 bg-amber-50 text-amber-900'
                  : 'border-slate-200 bg-white text-slate-700 hover:bg-slate-50'
              }`}
            >
              {effectiveOffline ? (
                <>
                  <WifiOff className="h-3.5 w-3.5" /> {!networkOnline ? 'Sin red detectada' : 'Modo Offline activo'}
                </>
              ) : (
                <>
                  <Wifi className="h-3.5 w-3.5" /> Simular modo Offline
                </>
              )}
            </button>
          </div>
        </div>
      </div>

      {/* Main Content */}
      <main className="mx-auto max-w-7xl px-6 py-8">
        {errorBanner && (
          <div className="mb-6 flex items-center justify-between gap-4 rounded-xl border border-red-200 bg-red-50 px-4 py-3 text-xs text-red-900">
            <span>{errorBanner}</span>
            <button
              type="button"
              onClick={() => setErrorBanner('')}
              className="font-semibold underline"
            >
              Cerrar
            </button>
          </div>
        )}

        {!user && authReady && (
          <div className="mb-6 flex flex-wrap items-center justify-between gap-4 rounded-xl border border-sky-200 bg-sky-50/70 px-5 py-4">
            <div>
              <p className="text-sm font-semibold text-slate-900">
                Conecta tu cuenta de Google para persistir paquetes en Firestore y sincronizar con Google Sheets
              </p>
              <p className="mt-0.5 text-xs text-slate-600">
                La autenticación verifica identidad del operador y habilita la emisión y auditoría de CVV.
              </p>
            </div>
            <GoogleSignInButton onClick={handleLogin} loading={authLoading} />
          </div>
        )}

        {activeTab === 'overview' && (
          <OverviewSection
            packages={packages}
            auditLogs={auditLogs}
            offlineQueue={offlineQueue}
            pilotConfig={pilotConfig}
            onSavePilotConfig={async (cfg) => {
              if (!user) return;
              await savePilotConfig(user.uid, cfg);
              setPilotConfig({ ...cfg, ownerId: user.uid });
            }}
            onNavigate={setActiveTab}
            onLoadSample={handleLoadSample}
            isBusy={isBusy}
            isAuthenticated={Boolean(user)}
          />
        )}

        {activeTab === 'packaging' && (
          <PackagingSection
            packages={packages}
            selectedPackageId={selectedPackageId}
            onSelectPackage={setSelectedPackageId}
            onCreatePackage={handleCreatePackage}
            onValidateMaterial={handleValidateMaterial}
            onLoadSample={handleLoadSample}
            isAuthenticated={Boolean(user)}
            isBusy={isBusy}
          />
        )}

        {activeTab === 'transfers' && (
          <TransfersSection
            packages={packages}
            selectedPackage={selectedPackage}
            onSelectPackage={setSelectedPackageId}
            events={events}
            cachedKnownNonces={cachedKnownNonces}
            trustedStationKeys={trustedStationKeys}
            onRegisterTrustedStation={handleRegisterTrustedStation}
            onSaveEventProof={handleSaveEventProof}
            isOffline={effectiveOffline}
            autoSyncOnReconnect={autoSyncOnReconnect}
            onToggleAutoSync={() => setAutoSyncOnReconnect((prev) => !prev)}
            offlineQueue={offlineQueue}
            onRecordOnlineTransfer={handleRecordOnlineTransfer}
            onEnqueueOfflineEvent={handleEnqueueOfflineEvent}
            onImportOfflineBatch={handleImportOfflineBatch}
            onSyncOfflineQueue={handleSyncOfflineQueue}
            operatorInfo={
              user
                ? {
                    uid: user.uid,
                    email: user.email || 'operador@tai.local',
                    displayName: user.displayName || user.email?.split('@')[0] || 'Operador TAI',
                  }
                : null
            }
            pilotConfig={pilotConfig}
            isAuthenticated={Boolean(user)}
            isBusy={isBusy}
          />
        )}

        {activeTab === 'audit' && (
          <CsgAuditSection
            packages={packages}
            selectedPackage={selectedPackage}
            events={events}
            auditLogs={auditLogs}
            eventProofs={eventProofs}
            trustedStationKeys={trustedStationKeys}
            pilotConfig={pilotConfig}
            accessToken={accessToken}
            isAuthenticated={Boolean(user)}
            onGoogleLogin={handleLogin}
            onSaveSheetConfig={async (spreadsheetId, spreadsheetTitle) => {
              if (!user) return;
              const base = pilotConfig || {
                solverOrg: 'Organización Postulante TAI',
                boxSupplier: 'Proveedor de maquila participante',
                trlLevel: 'TRL 4–5',
                pilotFacility: 'Centro Logístico Buenos Aires — YPF',
                spreadsheetId: '',
                spreadsheetTitle: '',
              };
              const next = { ...base, spreadsheetId, spreadsheetTitle };
              await savePilotConfig(user.uid, next);
              setPilotConfig({ ...next, ownerId: user.uid });
            }}
            onInvalidateCvv={async (pkg, event, reason) => {
              if (!user) return;
              await invalidateCvvByCsg({
                pkg,
                event,
                ownerId: user.uid,
                ownerEmail: user.email || 'auditor@tai.local',
                reason,
              });
            }}
            onLogSheetsSync={async (packageId, detail) => {
              if (!user) return;
              await logSheetsSyncAudit({
                ownerId: user.uid,
                ownerEmail: user.email || 'operador@tai.local',
                packageId,
                detail,
              });
            }}
          />
        )}

        {activeTab === 'hub' && <LogisticsHubSection />}
      </main>

      <footer className="mt-12 border-t border-slate-200 bg-white">
        <div className="mx-auto flex max-w-7xl flex-wrap items-center justify-between gap-4 px-6 py-5 text-xs text-slate-500">
          <p>
            TAI — Trazabilidad y Auditoría Inteligente · Diseño conceptual: Arturo Balderas
          </p>
          <p>
            Propuesta piloto para YPF · Compatible con SAP MM, Infor WMS y Unigis TMS sin reemplazo de sistemas
          </p>
        </div>
      </footer>
    </div>
  );
}

export default function App() {
  return (
    <ErrorBoundary>
      <TaiWorkspace />
    </ErrorBoundary>
  );
}
