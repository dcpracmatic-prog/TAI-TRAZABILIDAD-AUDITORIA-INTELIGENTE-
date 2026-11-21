import {
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
  type ChangeEvent,
  type FormEvent,
} from 'react';
import QrScanner, { type QrScannerResult } from 'react-qr-scanner';
import jsQR from 'jsqr';
import {
  AlertTriangle,
  ArrowRightLeft,
  Camera,
  CameraOff,
  CheckCircle2,
  CloudUpload,
  CopyCheck,
  ImageUp,
  RefreshCw,
  RotateCcw,
  ShieldCheck,
  Smartphone,
  WifiOff,
} from 'lucide-react';
import { generateNonce, getDeviceId, sealEventOnDevice } from '../lib/taiService';
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
  autoSyncOnReconnect: boolean;
  onToggleAutoSync: () => void;
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
    preSealed: {
      eventId: string;
      ciphertext: string;
      iv: string;
      authTag: string;
      csgSeal: string;
    };
    localTimestamp: string;
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

interface ParsedAcceptanceQr {
  packageId: string;
  eventType: 'dispatch' | 'receive' | 'return';
  nonce: string;
  receiverName: string;
  zone: string;
}

interface ValidatedAcceptanceQr extends ParsedAcceptanceQr {
  packageCode: string;
  capturedAt: string;
  isDuplicateNonce: boolean;
  duplicateReason?: string;
}

function isValidTransferEventType(value: string): value is 'dispatch' | 'receive' | 'return' {
  return value === 'dispatch' || value === 'receive' || value === 'return';
}

function parseAcceptanceQr(raw: string): ParsedAcceptanceQr | null {
  const trimmed = raw.trim();
  if (trimmed.startsWith('tai://accept|')) {
    const parts = trimmed.split('|');
    if (parts.length >= 4) {
      const packageId = parts[1]?.trim();
      const evt = parts[2]?.trim();
      const nonce = parts[3]?.trim();
      if (!packageId || !evt || !isValidTransferEventType(evt) || !nonce || nonce.length < 4) {
        return null;
      }
      return {
        packageId,
        eventType: evt,
        nonce,
        receiverName: parts[4]?.trim() || 'Receptor en sitio',
        zone: parts[5]?.trim() || 'Centro Logístico Buenos Aires',
      };
    }
  }
  if (trimmed.startsWith('tai://accept/')) {
    const rest = trimmed.replace('tai://accept/', '').split('/');
    if (rest.length >= 3) {
      const packageId = rest[0]?.trim();
      const evt = rest[1]?.trim();
      const nonce = rest[2]?.trim();
      if (!packageId || !evt || !isValidTransferEventType(evt) || !nonce || nonce.length < 4) {
        return null;
      }
      return {
        packageId,
        eventType: evt,
        nonce,
        receiverName: 'Receptor en sitio',
        zone: 'Centro Logístico Buenos Aires',
      };
    }
  }
  return null;
}

async function decodeQrFromImageFile(file: File): Promise<string | null> {
  const objectUrl = URL.createObjectURL(file);
  try {
    const img = await new Promise<HTMLImageElement>((resolve, reject) => {
      const el = new Image();
      el.onload = () => resolve(el);
      el.onerror = () => reject(new Error('No se pudo cargar la imagen.'));
      el.src = objectUrl;
    });

    const maxDim = 1200;
    const scale = Math.min(1, maxDim / Math.max(img.width, img.height, 1));
    const width = Math.max(1, Math.round(img.width * scale));
    const height = Math.max(1, Math.round(img.height * scale));

    const canvas = document.createElement('canvas');
    canvas.width = width;
    canvas.height = height;
    const ctx = canvas.getContext('2d');
    if (!ctx) return null;

    ctx.drawImage(img, 0, 0, width, height);
    const imageData = ctx.getImageData(0, 0, width, height);
    const decoded = jsQR(imageData.data, width, height, { inversionAttempts: 'attemptBoth' });
    return decoded?.data || null;
  } finally {
    URL.revokeObjectURL(objectUrl);
  }
}

export function TransfersSection({
  packages,
  selectedPackage,
  onSelectPackage,
  events,
  isOffline,
  autoSyncOnReconnect,
  onToggleAutoSync,
  offlineQueue,
  onRecordOnlineTransfer,
  onEnqueueOfflineEvent,
  onSyncOfflineQueue,
  isAuthenticated,
  isBusy,
}: TransfersSectionProps) {
  // Step 1: Receiver Device state
  const [eventType, setEventType] = useState<'dispatch' | 'receive' | 'return'>('receive');
  const [receiverName, setReceiverName] = useState('Módulo Mantenimiento Compresores');
  const [zone, setZone] = useState('Zona Operativa Sur · Dock Sud');
  const [acceptanceNonce, setAcceptanceNonce] = useState(() => generateNonce());
  const [receiverLocalSaved, setReceiverLocalSaved] = useState<string[]>([]);

  // Step 2: Deliverer Device camera scanner via react-qr-scanner
  const [cameraActive, setCameraActive] = useState(false);
  const [cameraLoading, setCameraLoading] = useState(false);
  const [useFallbackConstraints, setUseFallbackConstraints] = useState(false);
  const [cameraError, setCameraError] = useState('');
  const [manualQrInput, setManualQrInput] = useState('');
  const scanLockRef = useRef(false);
  const lastInvalidWarnRef = useRef(0);

  const [scannedAcceptance, setScannedAcceptance] = useState<ValidatedAcceptanceQr | null>(null);
  const [delivererName, setDelivererName] = useState('Transporte Interno BA-04');
  const [functionRole, setFunctionRole] = useState('Operador que Entrega');
  const [sealStatus, setSealStatus] = useState<SealStatus>('intact');
  const [observations, setObservations] = useState('Cierre TAI intacto. QR escaneado en sitio.');
  const [discrepancyNote, setDiscrepancyNote] = useState('');

  const [lastLocalCvv, setLastLocalCvv] = useState<{
    eventId: string;
    iv: string;
    authTag: string;
    csgSeal: string;
    capturedOffline: boolean;
  } | null>(null);
  const [sealingLocal, setSealingLocal] = useState(false);
  const [feedback, setFeedback] = useState<{ kind: 'ok' | 'warn'; msg: string } | null>(null);

  const acceptanceQrValue = selectedPackage
    ? `tai://accept|${selectedPackage.id}|${eventType}|${acceptanceNonce}|${receiverName.trim()}|${zone.trim()}`
    : '';

  const cameraConstraints = useMemo<MediaStreamConstraints>(
    () => ({
      audio: false,
      video: useFallbackConstraints ? true : { facingMode: { ideal: 'environment' } },
    }),
    [useFallbackConstraints]
  );

  const emptyQrArea = useMemo<[]>(() => [], []);

  const stopCameraScanner = useCallback(() => {
    scanLockRef.current = false;
    setCameraActive(false);
    setCameraLoading(false);
  }, []);

  useEffect(() => {
    return () => {
      stopCameraScanner();
    };
  }, [stopCameraScanner]);

  const validateAndApplyAcceptanceQr = useCallback(
    (raw: string, suppressTransientInvalid = false): boolean => {
      const parsed = parseAcceptanceQr(raw);
      if (!parsed) {
        if (!suppressTransientInvalid || Date.now() - lastInvalidWarnRef.current > 2000) {
          lastInvalidWarnRef.current = Date.now();
          setFeedback({
            kind: 'warn',
            msg: `El código escaneado (${raw.slice(0, 60)}) no corresponde a un QR de aceptación TAI válido (tai://accept|...).`,
          });
        }
        return false;
      }

      const targetPkg = packages.find(
        (p) => p.id === parsed.packageId || p.code === parsed.packageId
      );
      if (!targetPkg) {
        setFeedback({
          kind: 'warn',
          msg: `El paquete (${parsed.packageId}) del QR de aceptación no se encuentra registrado en esta unidad.`,
        });
        return false;
      }

      const duplicateInOffline = offlineQueue.some(
        (item) => item.acceptanceNonce === parsed.nonce
      );
      const duplicateInSynced = events.some(
        (ev) => ev.acceptanceNonce === parsed.nonce && ev.cvvState === 'valid'
      );

      const isDuplicateNonce = duplicateInOffline || duplicateInSynced;
      const duplicateReason = duplicateInOffline
        ? 'Este QR de aceptación ya tiene un CVV pendiente en la cola offline.'
        : duplicateInSynced
          ? 'Este QR de aceptación ya inició un evento sincronizado; reenviarlo se marcará como conflicto.'
          : undefined;

      onSelectPackage(targetPkg.id);
      setScannedAcceptance({
        ...parsed,
        packageId: targetPkg.id,
        packageCode: targetPkg.code,
        capturedAt: new Date().toISOString(),
        isDuplicateNonce,
        duplicateReason,
      });
      setEventType(parsed.eventType);
      setReceiverName(parsed.receiverName);
      setZone(parsed.zone);
      setAcceptanceNonce(parsed.nonce);
      setFeedback({
        kind: isDuplicateNonce ? 'warn' : 'ok',
        msg: isDuplicateNonce
          ? `QR capturado (${parsed.nonce}) con advertencia: ${duplicateReason}`
          : `QR de aceptación validado como inicio de ${EVENT_LABELS[parsed.eventType]} para ${targetPkg.code}. Ya puedes generar el CVV en dispositivo.`,
      });
      return true;
    },
    [packages, offlineQueue, events, onSelectPackage]
  );

  const handleCameraLoad = useCallback(() => {
    setCameraLoading(false);
    setCameraError('');
  }, []);

  const handleCameraError = useCallback(
    (err: unknown) => {
      const errName = err instanceof Error ? err.name : '';
      const errMsg = err instanceof Error ? err.message : String(err || '');

      if (
        !useFallbackConstraints &&
        (errName === 'OverconstrainedError' || errName === 'ConstraintNotSatisfiedError')
      ) {
        setUseFallbackConstraints(true);
        return;
      }

      setCameraActive(false);
      setCameraLoading(false);
      setCameraError(
        errMsg
          ? `No se pudo iniciar la cámara (${errMsg}). Puedes subir una imagen QR o usar "Leer QR mostrado".`
          : 'No se pudo acceder a la cámara en este navegador.'
      );
    },
    [useFallbackConstraints]
  );

  const handleCameraScan = useCallback(
    (result: QrScannerResult | string | null) => {
      if (!result || scanLockRef.current) return;
      const rawText = typeof result === 'string' ? result : result.text || '';
      if (!rawText.trim()) return;

      const accepted = validateAndApplyAcceptanceQr(rawText, true);
      if (accepted) {
        scanLockRef.current = true;
        setCameraActive(false);
        setCameraLoading(false);
      }
    },
    [validateAndApplyAcceptanceQr]
  );

  function startCameraScanner() {
    setCameraError('');
    setFeedback(null);
    scanLockRef.current = false;
    setCameraLoading(true);
    setCameraActive(true);
  }

  async function handleScanImageFile(e: ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0];
    if (!file) return;
    setCameraError('');
    try {
      stopCameraScanner();
      const decodedText = await decodeQrFromImageFile(file);
      if (!decodedText) {
        setCameraError('No se encontró ningún QR de aceptación válido en la imagen.');
        return;
      }
      validateAndApplyAcceptanceQr(decodedText);
    } catch {
      setCameraError('No se pudo procesar la imagen seleccionada.');
    } finally {
      e.target.value = '';
    }
  }

  function handleReceiverIssueQr() {
    if (!selectedPackage) return;
    const nextNonce = generateNonce();
    setAcceptanceNonce(nextNonce);
    setReceiverLocalSaved((prev) => [
      `${selectedPackage.code} · ${EVENT_LABELS[eventType]} · ${nextNonce} (${new Date().toLocaleTimeString()})`,
      ...prev.slice(0, 4),
    ]);
    setFeedback({
      kind: 'ok',
      msg: `QR de aceptación generado en el teléfono del receptor (${isOffline ? 'sin red, registrado localmente' : 'listo para escaneo'}).`,
    });
  }

  async function handleGenerateDeviceCvvAndSubmit(e: FormEvent) {
    e.preventDefault();
    if (!scannedAcceptance) {
      setFeedback({
        kind: 'warn',
        msg: 'Primero captura y valida el QR de aceptación del receptor para iniciar el evento de transferencia.',
      });
      return;
    }

    const targetPkg = packages.find((p) => p.id === scannedAcceptance.packageId) || selectedPackage;
    if (!targetPkg) return;

    if (offlineQueue.some((item) => item.acceptanceNonce === scannedAcceptance.nonce)) {
      setFeedback({
        kind: 'warn',
        msg: `El QR de aceptación (${scannedAcceptance.nonce}) ya fue sellado en la cola offline. Genera un nuevo QR de entrega para una nueva transferencia.`,
      });
      return;
    }

    setFeedback(null);
    setSealingLocal(true);

    try {
      const localTimestamp = new Date().toISOString();
      const activeNonce = scannedAcceptance.nonce;
      const activeEventType = scannedAcceptance.eventType;

      // ALWAYS generate CVV locally on the deliverer's device using Web Crypto API (AES-256-GCM + CSG)
      const sealed = await sealEventOnDevice({
        packageId: targetPkg.id,
        eventType: activeEventType,
        delivererName: delivererName.trim(),
        receiverName: receiverName.trim(),
        zone: zone.trim(),
        functionRole: functionRole.trim(),
        observations: observations.trim(),
        acceptanceNonce: activeNonce,
        localTimestamp,
        capturedOffline: isOffline,
      });

      setLastLocalCvv({
        eventId: sealed.eventId,
        iv: sealed.iv,
        authTag: sealed.authTag,
        csgSeal: sealed.csgSeal,
        capturedOffline: isOffline,
      });

      if (isOffline) {
        const nextSeq =
          offlineQueue.filter((item) => item.packageId === targetPkg.id).length + 1;
        onEnqueueOfflineEvent({
          localId: `LOC_${Date.now()}_${Math.random().toString(36).slice(2, 6)}`,
          eventId: sealed.eventId,
          packageId: targetPkg.id,
          packageCode: targetPkg.code,
          eventType: activeEventType,
          delivererName: delivererName.trim(),
          receiverName: receiverName.trim(),
          zone: zone.trim(),
          functionRole: functionRole.trim(),
          observations: observations.trim(),
          acceptanceNonce: activeNonce,
          offlineSequence: nextSeq,
          deviceId: getDeviceId(),
          localTimestamp,
          sealStatus,
          discrepancyNote: discrepancyNote.trim(),
          cvvCiphertext: sealed.ciphertext,
          cvvIv: sealed.iv,
          cvvAuthTag: sealed.authTag,
          csgSeal: sealed.csgSeal,
        });
        setFeedback({
          kind: 'ok',
          msg: `CVV ${sealed.eventId} generado localmente sin red y guardado en cola offline (secuencia #${nextSeq}).`,
        });
        setScannedAcceptance(null);
        setAcceptanceNonce(generateNonce());
        return;
      }

      const res = await onRecordOnlineTransfer({
        pkg: targetPkg,
        eventType: activeEventType,
        delivererName: delivererName.trim(),
        receiverName: receiverName.trim(),
        zone: zone.trim(),
        functionRole: functionRole.trim(),
        observations: observations.trim(),
        acceptanceNonce: activeNonce,
        sealStatus,
        discrepancyNote: discrepancyNote.trim(),
        preSealed: {
          eventId: sealed.eventId,
          ciphertext: sealed.ciphertext,
          iv: sealed.iv,
          authTag: sealed.authTag,
          csgSeal: sealed.csgSeal,
        },
        localTimestamp,
      });

      if (res.duplicateOrConflict) {
        setFeedback({
          kind: 'warn',
          msg: res.reason || 'Se detectó QR duplicado o conflicto en la transferencia.',
        });
      } else {
        setFeedback({
          kind: 'ok',
          msg: `CVV ${sealed.eventId} generado en dispositivo y sincronizado con la plataforma.`,
        });
        setScannedAcceptance(null);
        setAcceptanceNonce(generateNonce());
      }
    } finally {
      setSealingLocal(false);
    }
  }

  function handleSimulateDuplicateNonce() {
    const existingValid = events.find((ev) => ev.cvvState === 'valid');
    if (!existingValid || !selectedPackage) {
      setFeedback({
        kind: 'warn',
        msg: 'Primero registra al menos un evento válido para simular el re-escaneo de un QR duplicado.',
      });
      return;
    }
    setScannedAcceptance({
      packageId: selectedPackage.id,
      packageCode: selectedPackage.code,
      eventType,
      nonce: existingValid.acceptanceNonce,
      receiverName,
      zone,
      capturedAt: new Date().toISOString(),
      isDuplicateNonce: true,
      duplicateReason:
        'Nonce ya utilizado en un evento previo; al generar el CVV y sincronizar será rechazado como conflicto.',
    });
    setAcceptanceNonce(existingValid.acceptanceNonce);
    setFeedback({
      kind: 'warn',
      msg: `QR duplicado cargado (${existingValid.acceptanceNonce}). Al emitir el CVV y sincronizar, será rechazado como conflicto.`,
    });
  }

  return (
    <div className="space-y-6">
      {/* Package & Connectivity Header */}
      <div className="flex flex-wrap items-center justify-between gap-4 rounded-xl border border-slate-200 bg-white p-4">
        <div className="flex flex-wrap items-center gap-3">
          <label className="text-xs font-semibold text-slate-700">Unidad logística activa:</label>
          <select
            value={selectedPackage?.id || ''}
            onChange={(e) => {
              onSelectPackage(e.target.value);
              setScannedAcceptance(null);
            }}
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

        <div className="flex flex-wrap items-center gap-4 text-xs">
          <label className="inline-flex cursor-pointer items-center gap-2 text-slate-700">
            <input
              type="checkbox"
              checked={autoSyncOnReconnect}
              onChange={onToggleAutoSync}
              className="h-3.5 w-3.5 rounded border-slate-300 text-sky-700"
            />
            <span>Auto-sincronizar al recuperar red</span>
          </label>

          {isOffline ? (
            <span className="inline-flex items-center gap-1.5 font-semibold text-amber-800">
              <WifiOff className="h-4 w-4" /> Dispositivos sin conexión (CVV local en cola)
            </span>
          ) : (
            <span className="inline-flex items-center gap-1.5 font-medium text-emerald-700">
              <CheckCircle2 className="h-4 w-4" /> Red activa · Envío inmediato tras CVV local
            </span>
          )}
        </div>
      </div>

      {!selectedPackage ? (
        <div className="rounded-xl border border-slate-200 bg-white p-10 text-center">
          <p className="text-sm font-medium text-slate-700">
            Registra o carga una unidad TAI en "Embalaje y QR" para ejecutar el flujo receptor ↔ quien entrega.
          </p>
        </div>
      ) : (
        <div className="grid grid-cols-1 gap-6 lg:grid-cols-12">
          {/* Left: 2-Device Flow (Receiver QR -> Deliverer react-qr-scanner Camera -> On-Device CVV) */}
          <div className="space-y-6 lg:col-span-7">
            {/* Step 1: Receiver's Phone */}
            <div className="rounded-xl border border-slate-200 bg-white p-6">
              <div className="flex flex-wrap items-center justify-between gap-3 border-b border-slate-100 pb-4">
                <div className="flex items-start gap-2.5">
                  <Smartphone className="mt-0.5 h-5 w-5 shrink-0 text-sky-700" />
                  <div>
                    <h2 className="font-display text-base font-semibold text-slate-900">
                      1. Dispositivo del receptor · QR de aceptación
                    </h2>
                    <p className="mt-0.5 text-xs text-slate-500">
                      El receptor genera el QR ligado al paquete y a esta entrega (funciona incluso sin internet).
                    </p>
                  </div>
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
                      className={`rounded-md px-3 py-1 text-xs font-medium transition-colors whitespace-nowrap ${
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
                <div className="space-y-3 md:col-span-5">
                  <QrCodeDisplay
                    value={acceptanceQrValue}
                    label="QR de Aceptación (Receptor)"
                    caption={acceptanceNonce}
                    size={144}
                  />
                  <button
                    type="button"
                    onClick={handleReceiverIssueQr}
                    className="inline-flex w-full items-center justify-center gap-1.5 rounded-lg border border-slate-200 bg-white px-3 py-1.5 text-xs font-semibold text-slate-700 hover:bg-slate-50"
                  >
                    <RefreshCw className="h-3.5 w-3.5" /> Generar nuevo QR de entrega
                  </button>
                </div>

                <div className="space-y-3 md:col-span-7">
                  <div>
                    <label className="block text-xs font-medium text-slate-700">
                      Receptor (quien genera el QR)
                    </label>
                    <input
                      type="text"
                      value={receiverName}
                      onChange={(e) => setReceiverName(e.target.value)}
                      maxLength={120}
                      className="mt-1 w-full rounded-lg border border-slate-200 px-3 py-1.5 text-xs"
                    />
                  </div>
                  <div>
                    <label className="block text-xs font-medium text-slate-700">
                      Zona / Área de recepción
                    </label>
                    <input
                      type="text"
                      value={zone}
                      onChange={(e) => setZone(e.target.value)}
                      maxLength={120}
                      className="mt-1 w-full rounded-lg border border-slate-200 px-3 py-1.5 text-xs"
                    />
                  </div>

                  {receiverLocalSaved.length > 0 && (
                    <div className="rounded-lg border border-slate-200 bg-slate-50 p-3 text-[11px] text-slate-600">
                      <p className="font-semibold text-slate-800">
                        Registro local en teléfono del receptor:
                      </p>
                      <ul className="mt-1 space-y-0.5 font-mono">
                        {receiverLocalSaved.map((line, i) => (
                          <li key={i} className="truncate">
                            {line}
                          </li>
                        ))}
                      </ul>
                    </div>
                  )}
                </div>
              </div>
            </div>

            {/* Step 2 & 3: Deliverer / Issuer Device with react-qr-scanner Camera */}
            <div className="rounded-xl border border-slate-200 bg-white p-6">
              <div className="flex flex-wrap items-center justify-between gap-3 border-b border-slate-100 pb-4">
                <div className="flex items-start gap-2.5">
                  <Camera className="mt-0.5 h-5 w-5 shrink-0 text-sky-700" />
                  <div>
                    <h2 className="font-display text-base font-semibold text-slate-900">
                      2. Dispositivo de quien entrega · Lector QR por cámara (react-qr-scanner)
                    </h2>
                    <p className="mt-0.5 text-xs text-slate-500">
                      Captura el QR de aceptación para validarlo como inicio de transferencia y generar el CVV en dispositivo.
                    </p>
                  </div>
                </div>

                <div className="flex flex-wrap gap-2">
                  {cameraActive ? (
                    <button
                      type="button"
                      onClick={stopCameraScanner}
                      className="inline-flex items-center gap-1.5 rounded-lg bg-red-600 px-3 py-1.5 text-xs font-semibold text-white hover:bg-red-700"
                    >
                      <CameraOff className="h-3.5 w-3.5" /> Detener cámara
                    </button>
                  ) : (
                    <button
                      type="button"
                      onClick={startCameraScanner}
                      className="inline-flex items-center gap-1.5 rounded-lg bg-slate-900 px-3 py-1.5 text-xs font-semibold text-white hover:bg-slate-800"
                    >
                      <Camera className="h-3.5 w-3.5" />
                      Escanear con cámara
                    </button>
                  )}

                  <label className="inline-flex cursor-pointer items-center gap-1.5 rounded-lg border border-slate-200 bg-white px-3 py-1.5 text-xs font-semibold text-slate-700 hover:bg-slate-50">
                    <ImageUp className="h-3.5 w-3.5" /> Imagen QR
                    <input
                      type="file"
                      accept="image/*"
                      onChange={handleScanImageFile}
                      className="hidden"
                    />
                  </label>

                  <button
                    type="button"
                    onClick={() => validateAndApplyAcceptanceQr(acceptanceQrValue)}
                    className="inline-flex items-center gap-1.5 rounded-lg border border-slate-200 bg-white px-3 py-1.5 text-xs font-semibold text-slate-700 hover:bg-slate-50"
                  >
                    Leer QR mostrado
                  </button>

                  <button
                    type="button"
                    onClick={handleSimulateDuplicateNonce}
                    className="inline-flex items-center gap-1.5 rounded-lg border border-amber-200 bg-amber-50 px-3 py-1.5 text-xs font-medium text-amber-900 hover:bg-amber-100"
                  >
                    <CopyCheck className="h-3.5 w-3.5" /> Probar duplicado
                  </button>
                </div>
              </div>

              {/* react-qr-scanner Camera Viewport */}
              {cameraActive && (
                <div className="relative mt-4 overflow-hidden rounded-lg border border-slate-200 bg-slate-950">
                  <QrScanner
                    constraints={cameraConstraints}
                    resolution={640}
                    qrArea={emptyQrArea}
                    onLoad={handleCameraLoad}
                    onError={handleCameraError}
                    onScan={handleCameraScan}
                    muted
                    className="h-64 w-full object-cover"
                  />
                  <div className="pointer-events-none absolute inset-0 flex items-center justify-center">
                    <div className="h-44 w-44 rounded-lg border-2 border-sky-400/90 shadow-[0_0_0_9999px_rgba(2,6,23,0.35)]" />
                  </div>
                  {cameraLoading && (
                    <div className="absolute inset-0 flex items-center justify-center bg-slate-950/75 text-xs font-medium text-slate-200">
                      Iniciando cámara con react-qr-scanner...
                    </div>
                  )}
                </div>
              )}

              {cameraError && (
                <p className="mt-3 rounded-lg border border-amber-200 bg-amber-50 px-3 py-2 text-xs text-amber-900">
                  {cameraError}
                </p>
              )}

              {/* Direct manual QR string paste fallback */}
              <div className="mt-3 flex gap-2">
                <input
                  type="text"
                  value={manualQrInput}
                  onChange={(e) => setManualQrInput(e.target.value)}
                  placeholder="Pegar cadena QR escaneada (tai://accept|...)"
                  className="flex-1 rounded-lg border border-slate-200 px-3 py-1.5 font-mono text-xs text-slate-800 focus:border-sky-600 focus:outline-none"
                />
                <button
                  type="button"
                  disabled={!manualQrInput.trim()}
                  onClick={() => {
                    if (validateAndApplyAcceptanceQr(manualQrInput)) {
                      setManualQrInput('');
                    }
                  }}
                  className="rounded-lg border border-slate-300 bg-white px-3 py-1.5 text-xs font-semibold text-slate-800 hover:bg-slate-50 disabled:opacity-40"
                >
                  Validar QR
                </button>
              </div>

              <form onSubmit={handleGenerateDeviceCvvAndSubmit} className="mt-4 space-y-3.5">
                {scannedAcceptance ? (
                  <div
                    className={`rounded-lg border px-3.5 py-2.5 text-xs ${
                      scannedAcceptance.isDuplicateNonce
                        ? 'border-amber-300 bg-amber-50 text-amber-950'
                        : 'border-emerald-200 bg-emerald-50/70 text-emerald-950'
                    }`}
                  >
                    <div className="flex items-center justify-between gap-2">
                      <p className="font-semibold">
                        {scannedAcceptance.isDuplicateNonce
                          ? `QR duplicado detectado: ${EVENT_LABELS[scannedAcceptance.eventType]}`
                          : `Inicio de transferencia validado: ${EVENT_LABELS[scannedAcceptance.eventType]}`}
                      </p>
                      <button
                        type="button"
                        onClick={() => setScannedAcceptance(null)}
                        className="text-[11px] font-medium underline opacity-80 hover:opacity-100"
                      >
                        Limpiar
                      </button>
                    </div>
                    <p className="mt-0.5 font-mono text-[11px]">
                      Paquete: {scannedAcceptance.packageCode} · Nonce: {scannedAcceptance.nonce}
                    </p>
                    {scannedAcceptance.duplicateReason && (
                      <p className="mt-1 text-[11px] font-medium text-amber-900">
                        {scannedAcceptance.duplicateReason}
                      </p>
                    )}
                  </div>
                ) : (
                  <div className="rounded-lg border border-slate-200 bg-slate-50 px-3.5 py-2.5 text-xs text-slate-600">
                    Captura y valida el QR de aceptación del receptor con la cámara (o pulsa &quot;Leer QR mostrado&quot;) para iniciar el evento de transferencia y habilitar la generación del CVV.
                  </div>
                )}

                <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
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

                {lastLocalCvv && (
                  <div className="rounded-lg border border-slate-200 bg-slate-50 p-3 font-mono text-[11px] text-slate-700">
                    <p className="flex items-center gap-1.5 font-sans text-xs font-semibold text-slate-900">
                      <ShieldCheck className="h-4 w-4 text-emerald-700" />
                      Último CVV generado en dispositivo ({lastLocalCvv.capturedOffline ? 'Pendiente en cola offline' : 'Sincronizado'})
                    </p>
                    <p className="mt-1 truncate">Event ID: {lastLocalCvv.eventId}</p>
                    <p className="truncate">IV (AES-256-GCM): {lastLocalCvv.iv}</p>
                    <p className="truncate">Sello CSG: {lastLocalCvv.csgSeal}</p>
                  </div>
                )}

                <button
                  type="submit"
                  disabled={!isAuthenticated || isBusy || sealingLocal || !scannedAcceptance}
                  className="inline-flex w-full items-center justify-center gap-2 rounded-lg bg-sky-700 px-4 py-2.5 text-xs font-semibold text-white transition-colors hover:bg-sky-800 disabled:opacity-50"
                >
                  {eventType === 'return' ? (
                    <RotateCcw className="h-3.5 w-3.5" />
                  ) : (
                    <ArrowRightLeft className="h-3.5 w-3.5" />
                  )}
                  {sealingLocal
                    ? 'Generando CVV en dispositivo...'
                    : isOffline
                      ? 'Generar CVV local y guardar en cola offline'
                      : 'Generar CVV en dispositivo y sincronizar'}
                </button>

                {(!isAuthenticated || !scannedAcceptance) && (
                  <p className="text-[11px] text-slate-500">
                    {!isAuthenticated
                      ? 'Inicia sesión con tu cuenta para autorizar el registro de eventos.'
                      : 'Escanea o valida primero el QR de aceptación del receptor para habilitar la generación del CVV.'}
                  </p>
                )}
              </form>
            </div>
          </div>

          {/* Right: Offline Queue + Package Event History */}
          <div className="space-y-6 lg:col-span-5">
            {/* Step 3: Offline Queue & Manual/Auto Sync */}
            <div className="rounded-xl border border-slate-200 bg-white p-6">
              <div className="flex items-center justify-between gap-3 border-b border-slate-100 pb-3">
                <div>
                  <h3 className="font-display text-sm font-semibold text-slate-900">
                    3. Cola offline del dispositivo ({offlineQueue.length})
                  </h3>
                  <p className="text-[11px] text-slate-500">
                    CVV ya generado localmente; pendiente de envío a la plataforma.
                  </p>
                </div>
                <button
                  type="button"
                  disabled={isOffline || offlineQueue.length === 0 || isBusy || !isAuthenticated}
                  onClick={onSyncOfflineQueue}
                  className="inline-flex items-center gap-1.5 rounded-lg bg-slate-900 px-3 py-1.5 text-xs font-semibold text-white hover:bg-slate-800 disabled:opacity-40 whitespace-nowrap"
                >
                  <CloudUpload className="h-3.5 w-3.5" />
                  Sincronizar ahora
                </button>
              </div>

              {offlineQueue.length === 0 ? (
                <p className="mt-4 text-xs text-slate-500">
                  No hay CVV pendientes en cola local. Activa "Simular modo Offline" o desconecta la red para verificar la emisión offline en dispositivo.
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
                      <p className="mt-0.5 truncate font-mono text-[11px] text-slate-600">
                        CVV: {item.eventId} · CSG: {item.csgSeal.slice(0, 16)}…
                      </p>
                      <p className="mt-0.5 font-mono text-[11px] text-slate-500">
                        {item.localTimestamp}
                      </p>
                    </li>
                  ))}
                </ul>
              )}
            </div>

            {/* Package Event History */}
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
