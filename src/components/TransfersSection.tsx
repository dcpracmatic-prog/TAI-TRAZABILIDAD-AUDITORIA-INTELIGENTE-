import { useState, type FormEvent } from 'react';
import {
  AlertTriangle,
  ArrowRightLeft,
  CheckCircle2,
  CloudUpload,
  CopyCheck,
  RefreshCw,
  RotateCcw,
  WifiOff,
} from 'lucide-react';
import { generateNonce } from '../lib/taiService';
import type {
  OfflinePendingEvent,
  SealStatus,
  TaiPackage,
  TraceEvent,
  TraceEventType,
} from '../types/tai';
import { QrCodeDisplay } from './QrCodeDisplay';

interface TransfersSectionProps {
  packages: TaiPackage[];
  selectedPackage: TaiPackage | null;
  onSelectPackage: (id: string) => void;
  events: TraceEvent[];
  isOffline: boolean;
  offlineQueue: OfflinePendingEvent[];
  onRecordOnlineTransfer: (params: {
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
  }) => Promise<{ duplicateOrConflict: boolean; reason?: string }>;
  onEnqueueOfflineEvent: (item: OfflinePendingEvent) => void;
  onSyncOfflineQueue: () => Promise<void>;
  isAuthenticated: boolean;
  isBusy: boolean;
}

const EVENT_LABELS: Record<TraceEventType, string> = {
  pack: 'Embalaje inicial',
  dispatch: 'Despacho',
  receive: 'Recepción',
  return: 'Devolución',
  material_validation: 'Validación material',
  csg_invalidation: 'Invalidación CSG',
  conflict_detected: 'Conflicto detectado',
};

export function TransfersSection({
  packages,
  selectedPackage,
  onSelectPackage,
  events,
  isOffline,
  offlineQueue,
  onRecordOnlineTransfer,
  onEnqueueOfflineEvent,
  onSyncOfflineQueue,
  isAuthenticated,
  isBusy,
}: TransfersSectionProps) {
  const [eventType, setEventType] = useState<'dispatch' | 'receive' | 'return'>('receive');
  const [delivererName, setDelivererName] = useState('Transporte Interno BA-04');
  const [receiverName, setReceiverName] = useState('Módulo Mantenimiento Compresores');
  const [zone, setZone] = useState('Zona Operativa Sur · Dock Sud');
  const [functionRole, setFunctionRole] = useState('Supervisor de Recepción');
  const [sealStatus, setSealStatus] = useState<SealStatus>('intact');
  const [observations, setObservations] = useState('Cierre TAI intacto. Escaneo conforme.');
  const [discrepancyNote, setDiscrepancyNote] = useState('');
  const [acceptanceNonce, setAcceptanceNonce] = useState(() => generateNonce());
  const [feedback, setFeedback] = useState<{ kind: 'ok' | 'warn'; msg: string } | null>(null);

  const acceptanceQrValue = selectedPackage
    ? `tai://accept/${selectedPackage.id}/${eventType}/${acceptanceNonce}`
    : '';

  async function handleSubmitTransfer(e: FormEvent) {
    e.preventDefault();
    if (!selectedPackage) return;
    setFeedback(null);

    if (isOffline) {
      const nextSeq =
        offlineQueue.filter((item) => item.packageId === selectedPackage.id).length + 1;
      onEnqueueOfflineEvent({
        localId: `LOC_${Date.now()}_${Math.random().toString(36).slice(2, 6)}`,
        packageId: selectedPackage.id,
        packageCode: selectedPackage.code,
        eventType,
        delivererName: delivererName.trim(),
        receiverName: receiverName.trim(),
        zone: zone.trim(),
        functionRole: functionRole.trim(),
        observations: observations.trim(),
        acceptanceNonce,
        offlineSequence: nextSeq,
        deviceId: 'DISP-BA-OFFLINE-01',
        localTimestamp: new Date().toISOString(),
        sealStatus,
        discrepancyNote: discrepancyNote.trim(),
      });
      setFeedback({
        kind: 'ok',
        msg: `Evento capturado sin conexión (secuencia local #${nextSeq}). Sincroniza al recuperar red.`,
      });
      setAcceptanceNonce(generateNonce());
      return;
    }

    const res = await onRecordOnlineTransfer({
      pkg: selectedPackage,
      eventType,
      delivererName: delivererName.trim(),
      receiverName: receiverName.trim(),
      zone: zone.trim(),
      functionRole: functionRole.trim(),
      observations: observations.trim(),
      acceptanceNonce,
      sealStatus,
      discrepancyNote: discrepancyNote.trim(),
    });

    if (res.duplicateOrConflict) {
      setFeedback({
        kind: 'warn',
        msg: res.reason || 'Se detectó duplicado o conflicto en la transferencia.',
      });
    } else {
      setFeedback({
        kind: 'ok',
        msg: 'Transferencia aceptada y sellada con CVV (AES-256-GCM + CSG).',
      });
      setAcceptanceNonce(generateNonce());
    }
  }

  function handleSimulateDuplicateNonce() {
    const existingValid = events.find((ev) => ev.cvvState === 'valid');
    if (!existingValid) {
      setFeedback({
        kind: 'warn',
        msg: 'Primero registra al menos un evento válido para simular un re-escaneo duplicado.',
      });
      return;
    }
    setAcceptanceNonce(existingValid.acceptanceNonce);
    setFeedback({
      kind: 'warn',
      msg: `Nonce reutilizado cargado (${existingValid.acceptanceNonce}). Al enviar, el sistema detectará el QR duplicado.`,
    });
  }

  return (
    <div className="space-y-6">
      {/* Package Selector Strip */}
      <div className="flex flex-wrap items-center justify-between gap-4 rounded-xl border border-slate-200 bg-white p-4">
        <div className="flex flex-wrap items-center gap-3">
          <label className="text-xs font-semibold text-slate-700">Unidad logística activa:</label>
          <select
            value={selectedPackage?.id || ''}
            onChange={(e) => onSelectPackage(e.target.value)}
            className="rounded-lg border border-slate-200 bg-white px-3 py-1.5 font-mono text-xs text-slate-900 focus:border-sky-600 focus:outline-none"
          >
            {packages.length === 0 ? (
              <option value="">Sin paquetes registrados</option>
            ) : (
              packages.map((p) => (
                <option key={p.id} value={p.id}>
                  {p.code} — {p.fromArea} → {p.targetArea}
                </option>
              ))
            )}
          </select>
        </div>

        <div className="flex items-center gap-3 text-xs">
          {isOffline ? (
            <span className="inline-flex items-center gap-1.5 font-semibold text-amber-800">
              <WifiOff className="h-4 w-4" /> Modo Offline activo (captura local)
            </span>
          ) : (
            <span className="inline-flex items-center gap-1.5 font-medium text-emerald-700">
              <CheckCircle2 className="h-4 w-4" /> En línea · Emisión directa de CVV
            </span>
          )}
        </div>
      </div>

      {!selectedPackage ? (
        <div className="rounded-xl border border-slate-200 bg-white p-10 text-center">
          <p className="text-sm font-medium text-slate-700">
            Registra o carga una unidad TAI en "Embalaje y QR" para ejecutar transferencias y devoluciones.
          </p>
        </div>
      ) : (
        <div className="grid grid-cols-1 gap-6 lg:grid-cols-12">
          {/* Left: Handshake & Transfer Form */}
          <div className="rounded-xl border border-slate-200 bg-white p-6 lg:col-span-7">
            <div className="flex flex-wrap items-center justify-between gap-3 border-b border-slate-100 pb-4">
              <div>
                <h2 className="font-display text-base font-semibold text-slate-900">
                  Aceptación bilateral y devoluciones
                </h2>
                <p className="mt-1 text-xs text-slate-500">
                  Quien recibe genera su QR de aceptación; quien entrega lo escanea para emitir el CVV.
                </p>
              </div>
              <div className="flex items-center gap-1 rounded-lg bg-slate-100 p-1">
                {(
                  [
                    { id: 'dispatch', label: 'Despacho' },
                    { id: 'receive', label: 'Recepción' },
                    { id: 'return', label: 'Devolución' },
                  ] as const
                ).map((mode) => (
                  <button
                    key={mode.id}
                    type="button"
                    onClick={() => setEventType(mode.id)}
                    className={`rounded-md px-3 py-1.5 text-xs font-medium transition-colors whitespace-nowrap ${
                      eventType === mode.id
                        ? 'bg-white text-slate-900 shadow-sm'
                        : 'text-slate-600 hover:text-slate-900'
                    }`}
                  >
                    {mode.label}
                  </button>
                ))}
              </div>
            </div>

            <div className="mt-5 grid grid-cols-1 gap-6 md:grid-cols-12">
              {/* Receiver Acceptance QR */}
              <div className="space-y-3 md:col-span-5">
                <QrCodeDisplay
                  value={acceptanceQrValue}
                  label="QR de Aceptación (Receptor)"
                  caption={acceptanceNonce}
                  size={140}
                />
                <div className="flex flex-col gap-1.5">
                  <button
                    type="button"
                    onClick={() => setAcceptanceNonce(generateNonce())}
                    className="inline-flex items-center justify-center gap-1.5 rounded-lg border border-slate-200 bg-white px-3 py-1.5 text-xs font-medium text-slate-700 hover:bg-slate-50"
                  >
                    <RefreshCw className="h-3.5 w-3.5" /> Nuevo QR único
                  </button>
                  <button
                    type="button"
                    onClick={handleSimulateDuplicateNonce}
                    className="inline-flex items-center justify-center gap-1.5 rounded-lg border border-amber-200 bg-amber-50 px-3 py-1.5 text-xs font-medium text-amber-900 hover:bg-amber-100"
                  >
                    <CopyCheck className="h-3.5 w-3.5" /> Probar QR duplicado
                  </button>
                </div>
              </div>

              {/* Deliverer Scan & Metadata Form */}
              <form onSubmit={handleSubmitTransfer} className="space-y-3 md:col-span-7">
                <div className="grid grid-cols-2 gap-3">
                  <div>
                    <label className="block text-xs font-medium text-slate-700">Quien entrega</label>
                    <input
                      type="text"
                      value={delivererName}
                      onChange={(e) => setDelivererName(e.target.value)}
                      required
                      maxLength={120}
                      className="mt-1 w-full rounded-lg border border-slate-200 px-3 py-1.5 text-xs"
                    />
                  </div>
                  <div>
                    <label className="block text-xs font-medium text-slate-700">Quien recibe</label>
                    <input
                      type="text"
                      value={receiverName}
                      onChange={(e) => setReceiverName(e.target.value)}
                      required
                      maxLength={120}
                      className="mt-1 w-full rounded-lg border border-slate-200 px-3 py-1.5 text-xs"
                    />
                  </div>
                </div>

                <div className="grid grid-cols-2 gap-3">
                  <div>
                    <label className="block text-xs font-medium text-slate-700">Zona operativa</label>
                    <input
                      type="text"
                      value={zone}
                      onChange={(e) => setZone(e.target.value)}
                      required
                      maxLength={120}
                      className="mt-1 w-full rounded-lg border border-slate-200 px-3 py-1.5 text-xs"
                    />
                  </div>
                  <div>
                    <label className="block text-xs font-medium text-slate-700">Función / Rol</label>
                    <input
                      type="text"
                      value={functionRole}
                      onChange={(e) => setFunctionRole(e.target.value)}
                      required
                      maxLength={120}
                      className="mt-1 w-full rounded-lg border border-slate-200 px-3 py-1.5 text-xs"
                    />
                  </div>
                </div>

                <div>
                  <label className="block text-xs font-medium text-slate-700">
                    Inspección física del cierre TAI
                  </label>
                  <select
                    value={sealStatus}
                    onChange={(e) => setSealStatus(e.target.value as SealStatus)}
                    className="mt-1 w-full rounded-lg border border-slate-200 bg-white px-3 py-1.5 text-xs"
                  >
                    <option value="intact">Cierre intacto y etiqueta legible</option>
                    <option value="opened">Abierto por inspección autorizada</option>
                    <option value="damaged">Dañado / incidencia reportada</option>
                  </select>
                </div>

                {eventType === 'return' && (
                  <div>
                    <label className="block text-xs font-medium text-amber-900">
                      Cantidad observada y discrepancia de devolución
                    </label>
                    <input
                      type="text"
                      value={discrepancyNote}
                      onChange={(e) => setDiscrepancyNote(e.target.value)}
                      placeholder="Ej. Se devuelven 2 piezas sin uso; 1 empaque abierto."
                      required
                      maxLength={400}
                      className="mt-1 w-full rounded-lg border border-amber-300 bg-amber-50/40 px-3 py-1.5 text-xs"
                    />
                  </div>
                )}

                <div>
                  <label className="block text-xs font-medium text-slate-700">Observaciones</label>
                  <textarea
                    rows={2}
                    value={observations}
                    onChange={(e) => setObservations(e.target.value)}
                    maxLength={500}
                    className="mt-1 w-full rounded-lg border border-slate-200 px-3 py-1.5 text-xs"
                  />
                </div>

                {feedback && (
                  <p
                    className={`rounded-lg border px-3 py-2 text-xs font-medium ${
                      feedback.kind === 'warn'
                        ? 'border-amber-200 bg-amber-50 text-amber-900'
                        : 'border-emerald-200 bg-emerald-50 text-emerald-900'
                    }`}
                  >
                    {feedback.msg}
                  </p>
                )}

                <button
                  type="submit"
                  disabled={!isAuthenticated || isBusy}
                  className="inline-flex w-full items-center justify-center gap-2 rounded-lg bg-sky-700 px-4 py-2.5 text-xs font-semibold text-white transition-colors hover:bg-sky-800 disabled:opacity-50"
                >
                  {eventType === 'return' ? (
                    <RotateCcw className="h-3.5 w-3.5" />
                  ) : (
                    <ArrowRightLeft className="h-3.5 w-3.5" />
                  )}
                  {isOffline
                    ? 'Capturar evento en cola offline'
                    : eventType === 'return'
                      ? 'Registrar devolución y emitir CVV'
                      : 'Escanear aceptación y emitir CVV'}
                </button>
              </form>
            </div>
          </div>

          {/* Right: Offline Queue + Package History */}
          <div className="space-y-6 lg:col-span-5">
            {/* Offline Queue Card */}
            <div className="rounded-xl border border-slate-200 bg-white p-6">
              <div className="flex items-center justify-between border-b border-slate-100 pb-3">
                <div>
                  <h3 className="font-display text-sm font-semibold text-slate-900">
                    Cola de sincronización offline ({offlineQueue.length})
                  </h3>
                  <p className="text-[11px] text-slate-500">
                    Conserva secuencia, dispositivo y hora local hasta recuperar conexión.
                  </p>
                </div>
                <button
                  type="button"
                  disabled={isOffline || offlineQueue.length === 0 || isBusy || !isAuthenticated}
                  onClick={onSyncOfflineQueue}
                  className="inline-flex items-center gap-1.5 rounded-lg bg-slate-900 px-3 py-1.5 text-xs font-semibold text-white hover:bg-slate-800 disabled:opacity-40 whitespace-nowrap"
                >
                  <CloudUpload className="h-3.5 w-3.5" />
                  Sincronizar
                </button>
              </div>

              {offlineQueue.length === 0 ? (
                <p className="mt-4 text-xs text-slate-500">
                  No hay eventos pendientes offline. Activa "Modo Offline" en la barra superior para simular captura sin internet.
                </p>
              ) : (
                <ul className="mt-3 space-y-2">
                  {offlineQueue.map((item) => (
                    <li
                      key={item.localId}
                      className="rounded-lg border border-amber-200 bg-amber-50/50 p-3 text-xs"
                    >
                      <div className="flex items-center justify-between font-mono text-[11px] text-amber-900">
                        <span>
                          {item.packageCode} · Seq #{item.offlineSequence}
                        </span>
                        <span>{item.deviceId}</span>
                      </div>
                      <p className="mt-1 font-medium text-slate-800">
                        {EVENT_LABELS[item.eventType]}: {item.delivererName} → {item.receiverName}
                      </p>
                      <p className="mt-0.5 font-mono text-[11px] text-slate-500">
                        {item.localTimestamp}
                      </p>
                    </li>
                  ))}
                </ul>
              )}
            </div>

            {/* Package Event History (EPCIS-aligned) */}
            <div className="rounded-xl border border-slate-200 bg-white p-6">
              <h3 className="font-display text-sm font-semibold text-slate-900 border-b border-slate-100 pb-3">
                Historial de eventos — {selectedPackage.code}
              </h3>

              {events.length === 0 ? (
                <p className="mt-4 text-xs text-slate-500">Sin eventos registrados.</p>
              ) : (
                <ol className="mt-4 space-y-3">
                  {events.map((ev) => (
                    <li key={ev.id} className="rounded-lg border border-slate-200 p-3 text-xs">
                      <div className="flex items-center justify-between gap-2">
                        <span className="font-semibold text-slate-900">
                          {EVENT_LABELS[ev.eventType]}
                        </span>
                        {ev.cvvState === 'valid' ? (
                          <span className="inline-flex items-center gap-1 font-medium text-emerald-700">
                            <CheckCircle2 className="h-3.5 w-3.5" /> CVV válido
                          </span>
                        ) : ev.cvvState === 'invalidated_csg' ? (
                          <span className="inline-flex items-center gap-1 font-medium text-red-700">
                            <AlertTriangle className="h-3.5 w-3.5" /> Invalidado CSG
                          </span>
                        ) : (
                          <span className="inline-flex items-center gap-1 font-medium text-amber-700">
                            <AlertTriangle className="h-3.5 w-3.5" /> Conflicto
                          </span>
                        )}
                      </div>
                      <p className="mt-1 text-slate-700">
                        {ev.delivererName} → {ev.receiverName} · {ev.zone}
                      </p>
                      <p className="mt-1 font-mono text-[11px] text-slate-500">
                        {ev.id} · {ev.capturedOffline ? `Offline Seq #${ev.offlineSequence}` : 'Online'}
                      </p>
                      {ev.discrepancyNote && (
                        <p className="mt-1.5 text-[11px] font-medium text-amber-800">
                          Nota: {ev.discrepancyNote}
                        </p>
                      )}
                    </li>
                  ))}
                </ol>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
