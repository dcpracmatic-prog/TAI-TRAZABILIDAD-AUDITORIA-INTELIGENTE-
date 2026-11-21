import { useEffect, useId, useRef, useState, type ChangeEvent, type FormEvent } from 'react';
import { Html5Qrcode, Html5QrcodeSupportedFormats } from 'html5-qrcode';
import { Camera, ImageUp, Keyboard, X } from 'lucide-react';

interface QrScannerModalProps {
  open: boolean;
  title: string;
  subtitle: string;
  placeholder?: string;
  onDetected: (payload: string) => void;
  onClose: () => void;
}

export function QrScannerModal({
  open,
  title,
  subtitle,
  placeholder = 'tai://accept/...',
  onDetected,
  onClose,
}: QrScannerModalProps) {
  const rawId = useId();
  const readerId = `tai-qr-modal-${rawId.replace(/[^a-zA-Z0-9_-]/g, '')}`;
  const scannerRef = useRef<Html5Qrcode | null>(null);
  const detectedOnceRef = useRef(false);

  const [cameraState, setCameraState] = useState<'starting' | 'active' | 'unavailable'>('starting');
  const [cameraError, setCameraError] = useState('');
  const [manualValue, setManualValue] = useState('');

  useEffect(() => {
    if (!open) return;

    let cancelled = false;
    detectedOnceRef.current = false;
    setCameraState('starting');
    setCameraError('');

    const html5QrCode = new Html5Qrcode(readerId, {
      formatsToSupport: [Html5QrcodeSupportedFormats.QR_CODE],
      verbose: false,
    });
    scannerRef.current = html5QrCode;

    async function safeStop() {
      try {
        if (html5QrCode.isScanning) {
          await html5QrCode.stop();
        }
        html5QrCode.clear();
      } catch {
        // Ignore cleanup errors when stream was never started
      }
    }

    async function startScanner() {
      const config = { fps: 10, qrbox: { width: 220, height: 220 } };
      const handleSuccess = (decodedText: string) => {
        if (cancelled || detectedOnceRef.current) return;
        detectedOnceRef.current = true;
        safeStop().finally(() => {
          onDetected(decodedText);
        });
      };

      try {
        await html5QrCode.start({ facingMode: 'environment' }, config, handleSuccess, () => {});
        if (!cancelled) {
          setCameraState('active');
        } else {
          await safeStop();
        }
      } catch {
        // Fallback to first available camera device if facingMode environment fails on desktop
        try {
          const cameras = await Html5Qrcode.getCameras();
          if (cameras && cameras.length > 0 && !cancelled) {
            await html5QrCode.start(cameras[0].id, config, handleSuccess, () => {});
            if (!cancelled) {
              setCameraState('active');
              return;
            }
          }
          if (!cancelled) {
            setCameraState('unavailable');
            setCameraError(
              'No se detectó cámara activa o fue denegado el permiso. Puedes subir una imagen QR o ingresar el código.'
            );
          }
        } catch (err) {
          if (!cancelled) {
            setCameraState('unavailable');
            setCameraError(
              err instanceof Error
                ? `Cámara no disponible (${err.message}). Usa imagen QR o entrada manual.`
                : 'No se pudo iniciar la cámara.'
            );
          }
        }
      }
    }

    startScanner();

    return () => {
      cancelled = true;
      safeStop();
      scannerRef.current = null;
    };
  }, [open, readerId, onDetected]);

  async function handleImageUpload(e: ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0];
    if (!file) return;
    setCameraError('');
    try {
      const fileScanner =
        scannerRef.current ||
        new Html5Qrcode(readerId, {
          formatsToSupport: [Html5QrcodeSupportedFormats.QR_CODE],
          verbose: false,
        });
      if (fileScanner.isScanning) {
        await fileScanner.stop();
      }
      const decodedText = await fileScanner.scanFile(file, false);
      onDetected(decodedText);
    } catch {
      setCameraError('No se detectó ningún código QR válido en la imagen seleccionada.');
    } finally {
      e.target.value = '';
    }
  }

  function handleManualSubmit(e: FormEvent) {
    e.preventDefault();
    if (!manualValue.trim()) return;
    onDetected(manualValue.trim());
  }

  if (!open) return null;

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-slate-950/60 p-4"
      role="dialog"
      aria-modal="true"
      aria-labelledby="qr-scanner-title"
    >
      <div className="w-full max-w-lg rounded-xl border border-slate-200 bg-white p-6 shadow-xl">
        <div className="flex items-start justify-between gap-4 border-b border-slate-100 pb-3">
          <div className="flex items-start gap-2.5">
            <Camera className="mt-0.5 h-5 w-5 shrink-0 text-sky-700" />
            <div>
              <h3 id="qr-scanner-title" className="font-display text-base font-semibold text-slate-900">
                {title}
              </h3>
              <p className="mt-0.5 text-xs text-slate-500">{subtitle}</p>
            </div>
          </div>
          <button
            type="button"
            onClick={onClose}
            className="rounded-md p-1 text-slate-400 hover:bg-slate-100 hover:text-slate-700"
            aria-label="Cerrar escáner"
          >
            <X className="h-4 w-4" />
          </button>
        </div>

        <div className="mt-4 space-y-4">
          <div className="overflow-hidden rounded-lg border border-slate-200 bg-slate-900">
            <div id={readerId} className={cameraState === 'unavailable' ? 'hidden' : 'w-full'} />

            {cameraState !== 'active' && (
              <div className="flex h-48 flex-col items-center justify-center p-4 text-center text-xs text-slate-300">
                <Camera className="mb-2 h-7 w-7 text-slate-400" />
                {cameraState === 'starting'
                  ? 'Iniciando cámara con html5-qrcode...'
                  : 'Vista de cámara no disponible en este entorno.'}
              </div>
            )}
          </div>

          {cameraError && (
            <p className="rounded-lg border border-amber-200 bg-amber-50 px-3 py-2 text-xs text-amber-900">
              {cameraError}
            </p>
          )}

          <div className="flex flex-wrap items-center justify-between gap-3 rounded-lg border border-slate-200 bg-slate-50 p-3">
            <div className="flex items-center gap-2 text-xs text-slate-700">
              <ImageUp className="h-4 w-4 text-slate-500" />
              <span>¿Sin cámara activa? Escanea una imagen de QR:</span>
            </div>
            <label className="cursor-pointer rounded-md border border-slate-300 bg-white px-3 py-1.5 text-xs font-semibold text-slate-800 hover:bg-slate-100">
              Subir imagen QR
              <input
                type="file"
                accept="image/*"
                onChange={handleImageUpload}
                className="hidden"
              />
            </label>
          </div>

          <form onSubmit={handleManualSubmit} className="space-y-2 border-t border-slate-100 pt-3">
            <label className="flex items-center gap-1.5 text-xs font-medium text-slate-700">
              <Keyboard className="h-3.5 w-3.5 text-slate-500" />
              O ingresa el contenido del QR manualmente:
            </label>
            <div className="flex gap-2">
              <input
                type="text"
                value={manualValue}
                onChange={(e) => setManualValue(e.target.value)}
                placeholder={placeholder}
                className="flex-1 rounded-lg border border-slate-200 px-3 py-1.5 font-mono text-xs text-slate-900 focus:border-sky-600 focus:outline-none"
              />
              <button
                type="submit"
                disabled={!manualValue.trim()}
                className="rounded-lg bg-sky-700 px-3.5 py-1.5 text-xs font-semibold text-white hover:bg-sky-800 disabled:opacity-40"
              >
                Procesar
              </button>
            </div>
          </form>
        </div>
      </div>
    </div>
  );
}
