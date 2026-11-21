import { useEffect, useState } from 'react';
import {
  AlertOctagon,
  CheckCircle2,
  ExternalLink,
  FileSpreadsheet,
  FolderOpen,
  Lock,
  Paperclip,
  Plus,
  RefreshCw,
  ShieldAlert,
  ShieldCheck,
  Trash2,
  Upload,
} from 'lucide-react';
import { openGooglePicker, type PickedDriveFile } from '../lib/googlePicker';
import { verifyCvvLocally } from '../lib/localCrypto';
import {
  appendRowsToSheet,
  createTaiAuditSpreadsheet,
  getSpreadsheetMetadata,
  readSheetRange,
  type SpreadsheetMetadata,
} from '../lib/sheets';
import type { AuditLog, PilotConfig, TaiPackage, TraceEvent } from '../types/tai';
import { ConfirmModal } from './ConfirmModal';

interface CsgAuditSectionProps {
  packages: TaiPackage[];
  selectedPackage: TaiPackage | null;
  events: TraceEvent[];
  auditLogs: AuditLog[];
  pilotConfig: PilotConfig | null;
  accessToken: string | null;
  isAuthenticated: boolean;
  onGoogleLogin: () => Promise<void>;
  onSaveSheetConfig: (spreadsheetId: string, spreadsheetTitle: string) => Promise<void>;
  onInvalidateCvv: (pkg: TaiPackage, event: TraceEvent, reason: string) => Promise<void>;
  onLogSheetsSync: (packageId: string, detail: string) => Promise<void>;
}

interface PendingSheetSync {
  tabName: string;
  rows: Array<Array<string | number | boolean>>;
  summary: string;
}

export function CsgAuditSection({
  packages,
  selectedPackage,
  events,
  auditLogs,
  pilotConfig,
  accessToken,
  isAuthenticated,
  onGoogleLogin,
  onSaveSheetConfig,
  onInvalidateCvv,
  onLogSheetsSync,
}: CsgAuditSectionProps) {
  const [selectedEventId, setSelectedEventId] = useState<string>('');
  const [verifyResult, setVerifyResult] = useState<{
    valid: boolean;
    csgStatus: string;
    reason: string;
    decryptedPayload?: Record<string, unknown>;
  } | null>(null);
  const [verifying, setVerifying] = useState(false);

  // Google Sheets state
  const [sheetInput, setSheetInput] = useState(pilotConfig?.spreadsheetId || '');
  useEffect(() => {
    if (pilotConfig?.spreadsheetId && !sheetInput) {
      setSheetInput(pilotConfig.spreadsheetId);
    }
  }, [pilotConfig?.spreadsheetId, sheetInput]);
  const [newSheetTitle, setNewSheetTitle] = useState('TAI Piloto YPF — Bitácora Buenos Aires');
  const [sheetMeta, setSheetMeta] = useState<SpreadsheetMetadata | null>(null);
  const [selectedTab, setSelectedTab] = useState<string>('');
  const [sheetRows, setSheetRows] = useState<string[][]>([]);
  const [sheetBusy, setSheetBusy] = useState(false);
  const [pickerBusy, setPickerBusy] = useState(false);
  const [pickedDriveFiles, setPickedDriveFiles] = useState<PickedDriveFile[]>([]);
  const [sheetError, setSheetError] = useState('');
  const [sheetSuccess, setSheetSuccess] = useState('');
  const [pendingSync, setPendingSync] = useState<PendingSheetSync | null>(null);
  const [pendingTamperEvent, setPendingTamperEvent] = useState<TraceEvent | null>(null);

  const activeEvent =
    events.find((e) => e.id === selectedEventId) || events[0] || null;

  async function handleVerifyCvv(ev: TraceEvent, tamper = false) {
    setVerifying(true);
    setVerifyResult(null);
    try {
      const payload = tamper
        ? {
            ciphertext: ev.cvvCiphertext.slice(0, -4) + 'ffff',
            iv: ev.cvvIv,
            authTag: ev.cvvAuthTag,
            csgSeal: ev.csgSeal,
            packageId: ev.packageId,
            eventId: ev.id,
            eventType: ev.eventType,
            acceptanceNonce: ev.acceptanceNonce,
          }
        : {
            ciphertext: ev.cvvCiphertext,
            iv: ev.cvvIv,
            authTag: ev.cvvAuthTag,
            csgSeal: ev.csgSeal,
            packageId: ev.packageId,
            eventId: ev.id,
            eventType: ev.eventType,
            acceptanceNonce: ev.acceptanceNonce,
          };

      let data = await verifyCvvLocally(payload);
      if (!data.valid && !tamper) {
        const res = await fetch('/api/crypto/verify', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(payload),
        });
        if (res.ok) {
          const serverData = await res.json();
          if (serverData.valid) {
            data = serverData;
          }
        }
      }
      setVerifyResult(data);

      if (tamper && !data.valid && selectedPackage && ev.cvvState !== 'invalidated_csg') {
        await onInvalidateCvv(
          selectedPackage,
          ev,
          'Alteración detectada por AES-256-GCM / CSG durante prueba de auditoría.'
        );
      }
    } finally {
      setVerifying(false);
    }
  }

  async function handleCreateSpreadsheet() {
    if (!accessToken) return;
    setSheetBusy(true);
    setSheetError('');
    setSheetSuccess('');
    try {
      const meta = await createTaiAuditSpreadsheet(accessToken, newSheetTitle);
      setSheetMeta(meta);
      setSheetInput(meta.spreadsheetId);
      if (meta.tabs[0]) setSelectedTab(meta.tabs[0].title);
      await onSaveSheetConfig(meta.spreadsheetId, meta.title);
      setSheetSuccess(`Hoja creada: "${meta.title}"`);
    } catch (err) {
      setSheetError(err instanceof Error ? err.message : 'Error al crear hoja de cálculo');
    } finally {
      setSheetBusy(false);
    }
  }

  async function handleConnectSpreadsheet(explicitId?: string) {
    const targetInput = (explicitId ?? sheetInput).trim();
    if (!accessToken || !targetInput) return;
    setSheetBusy(true);
    setSheetError('');
    setSheetSuccess('');
    try {
      const meta = await getSpreadsheetMetadata(accessToken, targetInput);
      setSheetMeta(meta);
      setSheetInput(meta.spreadsheetId);
      const firstTab = meta.tabs[0]?.title || '';
      setSelectedTab(firstTab);
      await onSaveSheetConfig(meta.spreadsheetId, meta.title);
      if (firstTab) {
        const rows = await readSheetRange(accessToken, meta.spreadsheetId, firstTab);
        setSheetRows(rows);
      }
      setSheetSuccess(`Conectado a "${meta.title}" (${meta.tabs.length} pestañas detectadas).`);
    } catch (err) {
      setSheetError(err instanceof Error ? err.message : 'Error al conectar hoja');
    } finally {
      setSheetBusy(false);
    }
  }

  async function handlePickSpreadsheetFromDrive() {
    if (!accessToken) return;
    setPickerBusy(true);
    setSheetError('');
    setSheetSuccess('');
    try {
      const picked = await openGooglePicker({ accessToken, mode: 'spreadsheets' });
      if (picked.length > 0) {
        await handleConnectSpreadsheet(picked[0].id);
      }
    } catch (err) {
      setSheetError(
        err instanceof Error
          ? `${err.message} Si autorizaste la sesión antes de habilitar Drive, vuelve a iniciar sesión con Google.`
          : 'No se pudo abrir Google Picker.'
      );
    } finally {
      setPickerBusy(false);
    }
  }

  async function handlePickEvidenceFilesFromDrive() {
    if (!accessToken) return;
    setPickerBusy(true);
    setSheetError('');
    setSheetSuccess('');
    try {
      const picked = await openGooglePicker({ accessToken, mode: 'docs' });
      if (picked.length > 0) {
        setPickedDriveFiles((prev) => {
          const seen = new Set(prev.map((item) => item.id));
          const merged = [...prev];
          for (const file of picked) {
            if (!seen.has(file.id)) {
              seen.add(file.id);
              merged.unshift(file);
            }
          }
          return merged;
        });
        setSheetSuccess(
          `Se seleccionaron ${picked.length} documento(s) desde Google Drive con Google Picker.`
        );
      }
    } catch (err) {
      setSheetError(
        err instanceof Error
          ? `${err.message} Si autorizaste la sesión antes de habilitar Drive, vuelve a iniciar sesión con Google.`
          : 'No se pudo abrir Google Picker.'
      );
    } finally {
      setPickerBusy(false);
    }
  }

  async function handleReadTab(tabName: string) {
    if (!accessToken || !sheetMeta) return;
    setSelectedTab(tabName);
    setSheetBusy(true);
    setSheetError('');
    try {
      const rows = await readSheetRange(accessToken, sheetMeta.spreadsheetId, tabName);
      setSheetRows(rows);
    } catch (err) {
      setSheetError(err instanceof Error ? err.message : 'No se pudo leer la pestaña');
    } finally {
      setSheetBusy(false);
    }
  }

  function preparePackagesSync() {
    if (!sheetMeta) return;
    const targetTab =
      sheetMeta.tabs.find((t) => t.title === 'Paquetes')?.title ||
      selectedTab ||
      sheetMeta.tabs[0]?.title;
    if (!targetTab) return;

    const rows = packages.map((p) => [
      p.id,
      p.code,
      p.fromArea,
      p.targetArea,
      p.zone,
      p.contentSummary,
      p.quantity,
      p.unit,
      p.identificationStatus,
      p.sealStatus,
      p.lifecycleStatus,
    ]);
    setPendingSync({
      tabName: targetTab,
      rows,
      summary: `Se agregarán ${rows.length} fila(s) de unidades TAI a la pestaña "${targetTab}" de "${sheetMeta.title}".`,
    });
  }

  function prepareAuditSync() {
    if (!sheetMeta) return;
    const targetTab =
      sheetMeta.tabs.find((t) => t.title === 'Auditoria_Maestra')?.title ||
      selectedTab ||
      sheetMeta.tabs[0]?.title;
    if (!targetTab) return;

    const rows = auditLogs.map((l) => [
      l.id,
      l.packageId,
      l.action,
      l.severity,
      l.detail,
      l.actorEmail,
    ]);
    setPendingSync({
      tabName: targetTab,
      rows,
      summary: `Se agregarán ${rows.length} fila(s) de auditoría maestra a la pestaña "${targetTab}" de "${sheetMeta.title}".`,
    });
  }

  async function executePendingSync() {
    if (!pendingSync || !accessToken || !sheetMeta) return;
    setSheetBusy(true);
    setSheetError('');
    setSheetSuccess('');
    try {
      const res = await appendRowsToSheet(
        accessToken,
        sheetMeta.spreadsheetId,
        pendingSync.tabName,
        pendingSync.rows
      );
      await onLogSheetsSync(
        packages[0]?.id || 'PILOT_SHEETS_SYNC',
        `Sincronizadas ${res.updatedRows} filas hacia Google Sheets (${sheetMeta.title} · ${pendingSync.tabName}).`
      );
      const updated = await readSheetRange(
        accessToken,
        sheetMeta.spreadsheetId,
        pendingSync.tabName
      );
      setSelectedTab(pendingSync.tabName);
      setSheetRows(updated);
      setSheetSuccess(
        `Sincronización completada: ${res.updatedRows} filas agregadas en "${pendingSync.tabName}".`
      );
    } catch (err) {
      setSheetError(err instanceof Error ? err.message : 'Error al escribir en Google Sheets');
    } finally {
      setSheetBusy(false);
      setPendingSync(null);
    }
  }

  return (
    <div className="space-y-6">
      {/* Row 1: AES-256-GCM + CSG Verifier & Master Audit Trail */}
      <div className="grid grid-cols-1 gap-6 lg:grid-cols-12">
        {/* Crypto & CSG Verification */}
        <div className="rounded-xl border border-slate-200 bg-white p-6 lg:col-span-6">
          <div className="flex items-center justify-between border-b border-slate-100 pb-4">
            <div>
              <h2 className="font-display text-base font-semibold text-slate-900">
                Verificación AES-256-GCM y sellado CSG
              </h2>
              <p className="mt-1 text-xs text-slate-500">
                Detecta alteraciones o uso fuera de flujo; la invalidación CSG conserva el historial maestro.
              </p>
            </div>
            <Lock className="h-5 w-5 text-slate-400" />
          </div>

          {events.length === 0 ? (
            <p className="mt-4 text-xs text-slate-500">
              Selecciona un paquete con eventos emitidos para inspeccionar y verificar su CVV criptográfico.
            </p>
          ) : (
            <div className="mt-4 space-y-4">
              <div>
                <label className="block text-xs font-medium text-slate-700">
                  Evento CVV a inspeccionar ({selectedPackage?.code})
                </label>
                <select
                  value={activeEvent?.id || ''}
                  onChange={(e) => {
                    setSelectedEventId(e.target.value);
                    setVerifyResult(null);
                  }}
                  className="mt-1 w-full rounded-lg border border-slate-200 bg-white px-3 py-2 font-mono text-xs text-slate-900"
                >
                  {events.map((ev) => (
                    <option key={ev.id} value={ev.id}>
                      {ev.id} · {ev.eventType} ({ev.cvvState})
                    </option>
                  ))}
                </select>
              </div>

              {activeEvent && (
                <>
                  <div className="space-y-2 rounded-lg border border-slate-200 bg-slate-50 p-3 font-mono text-[11px] text-slate-700">
                    <p className="truncate">
                      <span className="font-semibold text-slate-900">IV:</span> {activeEvent.cvvIv}
                    </p>
                    <p className="truncate">
                      <span className="font-semibold text-slate-900">AuthTag:</span>{' '}
                      {activeEvent.cvvAuthTag}
                    </p>
                    <p className="truncate">
                      <span className="font-semibold text-slate-900">Sello CSG:</span>{' '}
                      {activeEvent.csgSeal}
                    </p>
                    <p className="truncate">
                      <span className="font-semibold text-slate-900">Ciphertext:</span>{' '}
                      {activeEvent.cvvCiphertext}
                    </p>
                  </div>

                  <div className="flex flex-wrap gap-2">
                    <button
                      type="button"
                      disabled={verifying}
                      onClick={() => handleVerifyCvv(activeEvent, false)}
                      className="inline-flex items-center gap-1.5 rounded-lg bg-sky-700 px-3.5 py-2 text-xs font-semibold text-white hover:bg-sky-800 disabled:opacity-50"
                    >
                      <ShieldCheck className="h-3.5 w-3.5" />
                      Verificar integridad CVV
                    </button>
                    <button
                      type="button"
                      disabled={verifying || activeEvent.cvvState === 'invalidated_csg'}
                      onClick={() => setPendingTamperEvent(activeEvent)}
                      className="inline-flex items-center gap-1.5 rounded-lg border border-red-200 bg-red-50 px-3.5 py-2 text-xs font-semibold text-red-800 hover:bg-red-100 disabled:opacity-50"
                    >
                      <ShieldAlert className="h-3.5 w-3.5" />
                      Simular alteración CSG
                    </button>
                  </div>
                </>
              )}

              {verifyResult && (
                <div
                  className={`rounded-lg border p-3 text-xs ${
                    verifyResult.valid
                      ? 'border-emerald-200 bg-emerald-50 text-emerald-950'
                      : 'border-red-200 bg-red-50 text-red-950'
                  }`}
                >
                  <p className="flex items-center gap-1.5 font-semibold">
                    {verifyResult.valid ? (
                      <CheckCircle2 className="h-4 w-4 text-emerald-700" />
                    ) : (
                      <AlertOctagon className="h-4 w-4 text-red-700" />
                    )}
                    Estado CSG: {verifyResult.csgStatus}
                  </p>
                  <p className="mt-1">{verifyResult.reason}</p>
                  {verifyResult.decryptedPayload && (
                    <pre className="mt-2 overflow-x-auto rounded bg-white/80 p-2 font-mono text-[11px] text-slate-800">
                      {JSON.stringify(verifyResult.decryptedPayload, null, 2)}
                    </pre>
                  )}
                </div>
              )}
            </div>
          )}
        </div>

        {/* Master Immutable Audit Log */}
        <div className="rounded-xl border border-slate-200 bg-white p-6 lg:col-span-6">
          <div className="flex items-center justify-between border-b border-slate-100 pb-4">
            <div>
              <h2 className="font-display text-base font-semibold text-slate-900">
                Bitácora maestra de auditoría ({auditLogs.length})
              </h2>
              <p className="mt-1 text-xs text-slate-500">
                Registro append-only protegido: nunca se borra ante invalidaciones de documentos.
              </p>
            </div>
          </div>

          {auditLogs.length === 0 ? (
            <p className="mt-4 text-xs text-slate-500">
              Aún no hay eventos en la bitácora maestra.
            </p>
          ) : (
            <div className="mt-4 max-h-80 overflow-y-auto pr-1">
              <ul className="space-y-2.5">
                {auditLogs.map((log) => (
                  <li
                    key={log.id}
                    className="rounded-lg border border-slate-200 bg-slate-50/60 p-3 text-xs"
                  >
                    <div className="flex items-center justify-between gap-2">
                      <span className="font-mono font-semibold text-slate-900">{log.action}</span>
                      <span
                        className={`font-medium ${
                          log.severity === 'critical'
                            ? 'text-red-700'
                            : log.severity === 'warning'
                              ? 'text-amber-700'
                              : 'text-emerald-700'
                        }`}
                      >
                        {log.severity}
                      </span>
                    </div>
                    <p className="mt-1 text-slate-700">{log.detail}</p>
                    <p className="mt-1 font-mono text-[11px] text-slate-500">
                      {log.packageId} · {log.actorEmail}
                    </p>
                  </li>
                ))}
              </ul>
            </div>
          )}
        </div>
      </div>

      {/* Row 2: Google Sheets & Google Picker (Drive) Integration */}
      <div className="rounded-xl border border-slate-200 bg-white p-6">
        <div className="flex flex-wrap items-center justify-between gap-4 border-b border-slate-100 pb-4">
          <div className="flex items-start gap-3">
            <FileSpreadsheet className="mt-0.5 h-5 w-5 text-emerald-700" />
            <div>
              <h2 className="font-display text-base font-semibold text-slate-900">
                Google Drive Picker y Sincronización con Google Sheets
              </h2>
              <p className="mt-1 text-xs text-slate-500">
                Selecciona hojas de cálculo o documentos de respaldo en tu Google Drive con Google Picker, o crea una bitácora piloto nueva.
              </p>
            </div>
          </div>

          <div className="flex flex-wrap items-center gap-2">
            {isAuthenticated && accessToken && (
              <button
                type="button"
                onClick={onGoogleLogin}
                className="inline-flex items-center gap-1.5 rounded-lg border border-slate-200 bg-white px-3 py-1.5 text-xs font-medium text-slate-700 hover:bg-slate-50"
              >
                <RefreshCw className="h-3.5 w-3.5" /> Reautorizar Drive / Sheets
              </button>
            )}
            {sheetMeta && (
              <a
                href={sheetMeta.spreadsheetUrl}
                target="_blank"
                rel="noopener noreferrer"
                className="inline-flex items-center gap-1.5 rounded-lg border border-slate-200 px-3 py-1.5 text-xs font-medium text-sky-700 hover:bg-slate-50"
              >
                Abrir en Google Sheets <ExternalLink className="h-3.5 w-3.5" />
              </a>
            )}
          </div>
        </div>

        {!isAuthenticated || !accessToken ? (
          <div className="mt-5 flex flex-wrap items-center justify-between gap-4 rounded-lg border border-slate-200 bg-slate-50 p-4">
            <p className="text-xs text-slate-700">
              Conecta tu cuenta de Google con permisos de Google Drive y Google Sheets para usar Google Picker, seleccionar hojas y sincronizar bitácoras.
            </p>
            <button
              type="button"
              onClick={onGoogleLogin}
              className="rounded-lg bg-slate-900 px-4 py-2 text-xs font-semibold text-white hover:bg-slate-800 whitespace-nowrap"
            >
              Autorizar Google Drive y Sheets
            </button>
          </div>
        ) : (
          <div className="mt-5 space-y-5">
            <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
              {/* Create new Sheet */}
              <div className="rounded-lg border border-slate-200 p-4">
                <p className="text-xs font-semibold text-slate-800">
                  Crear nueva hoja de auditoría TAI
                </p>
                <div className="mt-2 flex gap-2">
                  <input
                    type="text"
                    value={newSheetTitle}
                    onChange={(e) => setNewSheetTitle(e.target.value)}
                    className="flex-1 rounded-lg border border-slate-200 px-3 py-1.5 text-xs"
                  />
                  <button
                    type="button"
                    disabled={sheetBusy || pickerBusy}
                    onClick={handleCreateSpreadsheet}
                    className="inline-flex items-center gap-1.5 rounded-lg bg-emerald-700 px-3.5 py-1.5 text-xs font-semibold text-white hover:bg-emerald-800 disabled:opacity-50 whitespace-nowrap"
                  >
                    <Plus className="h-3.5 w-3.5" /> Crear hoja
                  </button>
                </div>
              </div>

              {/* Connect existing Sheet via Google Picker or URL/ID */}
              <div className="rounded-lg border border-slate-200 p-4">
                <p className="text-xs font-semibold text-slate-800">
                  Conectar hoja existente (Google Picker o URL / ID)
                </p>
                <div className="mt-2 flex flex-wrap gap-2">
                  <input
                    type="text"
                    value={sheetInput}
                    onChange={(e) => setSheetInput(e.target.value)}
                    placeholder="https://docs.google.com/spreadsheets/d/... o ID"
                    className="min-w-[180px] flex-1 rounded-lg border border-slate-200 px-3 py-1.5 font-mono text-xs"
                  />
                  <button
                    type="button"
                    disabled={sheetBusy || pickerBusy}
                    onClick={handlePickSpreadsheetFromDrive}
                    className="inline-flex items-center gap-1.5 rounded-lg bg-sky-700 px-3.5 py-1.5 text-xs font-semibold text-white hover:bg-sky-800 disabled:opacity-50 whitespace-nowrap"
                  >
                    <FolderOpen className="h-3.5 w-3.5" /> Elegir con Picker
                  </button>
                  <button
                    type="button"
                    disabled={sheetBusy || pickerBusy || !sheetInput.trim()}
                    onClick={() => handleConnectSpreadsheet()}
                    className="inline-flex items-center gap-1.5 rounded-lg border border-slate-300 bg-white px-3.5 py-1.5 text-xs font-semibold text-slate-800 hover:bg-slate-50 disabled:opacity-50 whitespace-nowrap"
                  >
                    <RefreshCw className="h-3.5 w-3.5" /> Conectar
                  </button>
                </div>
              </div>
            </div>

            {/* Google Picker for Supporting Drive Evidence Documents */}
            <div className="rounded-lg border border-slate-200 bg-slate-50/70 p-4">
              <div className="flex flex-wrap items-center justify-between gap-3">
                <div className="flex items-start gap-2.5">
                  <Paperclip className="mt-0.5 h-4 w-4 text-sky-700" />
                  <div>
                    <p className="text-xs font-semibold text-slate-900">
                      Documentos y remitos en Google Drive (Google Picker)
                    </p>
                    <p className="text-[11px] text-slate-500">
                      Adjunta o sube archivos de respaldo (remitos, especificaciones técnicas, fotos) desde tu Drive sin conceder acceso amplio a toda tu cuenta.
                    </p>
                  </div>
                </div>
                <button
                  type="button"
                  disabled={pickerBusy || sheetBusy}
                  onClick={handlePickEvidenceFilesFromDrive}
                  className="inline-flex items-center gap-1.5 rounded-lg border border-slate-300 bg-white px-3.5 py-1.5 text-xs font-semibold text-slate-800 hover:bg-slate-100 disabled:opacity-50 whitespace-nowrap"
                >
                  <FolderOpen className="h-3.5 w-3.5 text-sky-700" />
                  {pickerBusy ? 'Abriendo Picker...' : 'Seleccionar archivos de Drive'}
                </button>
              </div>

              {pickedDriveFiles.length > 0 && (
                <ul className="mt-3 divide-y divide-slate-200 rounded-lg border border-slate-200 bg-white">
                  {pickedDriveFiles.map((file) => (
                    <li
                      key={file.id}
                      className="flex flex-wrap items-center justify-between gap-2 px-3 py-2 text-xs"
                    >
                      <div className="min-w-0 flex-1">
                        <p className="truncate font-medium text-slate-900">{file.name}</p>
                        <p className="truncate font-mono text-[11px] text-slate-500">
                          {file.mimeType} · ID: {file.id}
                        </p>
                      </div>
                      <div className="flex items-center gap-2">
                        <a
                          href={file.url}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="inline-flex items-center gap-1 rounded-md border border-slate-200 px-2.5 py-1 text-[11px] font-medium text-sky-700 hover:bg-slate-50"
                        >
                          Abrir <ExternalLink className="h-3 w-3" />
                        </a>
                        <button
                          type="button"
                          onClick={() =>
                            setPickedDriveFiles((prev) => prev.filter((item) => item.id !== file.id))
                          }
                          aria-label={`Quitar ${file.name}`}
                          className="rounded-md p-1 text-slate-400 hover:bg-slate-100 hover:text-red-600"
                        >
                          <Trash2 className="h-3.5 w-3.5" />
                        </button>
                      </div>
                    </li>
                  ))}
                </ul>
              )}
            </div>

            {sheetError && (
              <p className="rounded-lg border border-red-200 bg-red-50 px-3 py-2 text-xs text-red-800">
                {sheetError}
              </p>
            )}
            {sheetSuccess && (
              <p className="rounded-lg border border-emerald-200 bg-emerald-50 px-3 py-2 text-xs text-emerald-800">
                {sheetSuccess}
              </p>
            )}

            {sheetMeta && (
              <div className="space-y-4">
                <div className="flex flex-wrap items-center justify-between gap-3">
                  <div className="flex flex-wrap items-center gap-1.5 rounded-lg bg-slate-100 p-1">
                    {sheetMeta.tabs.map((tab) => (
                      <button
                        key={tab.sheetId}
                        type="button"
                        onClick={() => handleReadTab(tab.title)}
                        className={`rounded-md px-3 py-1 text-xs font-medium transition-colors ${
                          selectedTab === tab.title
                            ? 'bg-white text-slate-900 shadow-sm'
                            : 'text-slate-600 hover:text-slate-900'
                        }`}
                      >
                        {tab.title}
                      </button>
                    ))}
                  </div>

                  <div className="flex flex-wrap gap-2">
                    <button
                      type="button"
                      disabled={sheetBusy || packages.length === 0}
                      onClick={preparePackagesSync}
                      className="inline-flex items-center gap-1.5 rounded-lg bg-sky-700 px-3.5 py-1.5 text-xs font-semibold text-white hover:bg-sky-800 disabled:opacity-50"
                    >
                      <Upload className="h-3.5 w-3.5" /> Exportar paquetes ({packages.length})
                    </button>
                    <button
                      type="button"
                      disabled={sheetBusy || auditLogs.length === 0}
                      onClick={prepareAuditSync}
                      className="inline-flex items-center gap-1.5 rounded-lg border border-slate-300 bg-white px-3.5 py-1.5 text-xs font-semibold text-slate-800 hover:bg-slate-50 disabled:opacity-50"
                    >
                      <Upload className="h-3.5 w-3.5" /> Exportar auditoría ({auditLogs.length})
                    </button>
                  </div>
                </div>

                {/* Preview Table */}
                <div className="overflow-x-auto rounded-lg border border-slate-200">
                  {sheetRows.length === 0 ? (
                    <p className="p-4 text-xs text-slate-500">
                      La pestaña "{selectedTab}" está vacía o aún no se ha leído.
                    </p>
                  ) : (
                    <table className="w-full text-left text-xs">
                      <tbody className="divide-y divide-slate-100">
                        {sheetRows.map((row, rIdx) => (
                          <tr key={rIdx} className={rIdx === 0 ? 'bg-slate-50 font-semibold text-slate-900' : ''}>
                            {row.map((cell, cIdx) => (
                              <td key={cIdx} className="whitespace-nowrap px-3 py-2 text-slate-700">
                                {cell}
                              </td>
                            ))}
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  )}
                </div>
              </div>
            )}
          </div>
        )}
      </div>

      {/* Explicit Confirmation Modal for Google Sheets Writes */}
      <ConfirmModal
        open={Boolean(pendingSync)}
        title="Confirmar escritura en Google Sheets"
        description={pendingSync?.summary || ''}
        details={
          pendingSync
            ? [
                `Hoja destino: ${sheetMeta?.title ?? ''}`,
                `Pestaña: ${pendingSync.tabName}`,
                `Filas a insertar: ${pendingSync.rows.length}`,
              ]
            : []
        }
        confirmLabel="Confirmar exportación"
        busy={sheetBusy}
        onConfirm={executePendingSync}
        onCancel={() => setPendingSync(null)}
      />

      {/* Confirmation Modal for CSG Tamper Simulation */}
      <ConfirmModal
        open={Boolean(pendingTamperEvent)}
        title="Simular alteración fuera de flujo (CSG)"
        description="Se enviará un AuthTag alterado al verificador AES-256-GCM. El protocolo CSG invalidará este CVV, conservando el registro maestro en la bitácora de auditoría."
        details={
          pendingTamperEvent
            ? [`CVV afectado: ${pendingTamperEvent.id}`, `Paquete: ${selectedPackage?.code ?? ''}`]
            : []
        }
        confirmLabel="Ejecutar prueba CSG"
        danger
        busy={verifying}
        onConfirm={async () => {
          const ev = pendingTamperEvent;
          setPendingTamperEvent(null);
          if (ev) await handleVerifyCvv(ev, true);
        }}
        onCancel={() => setPendingTamperEvent(null)}
      />
    </div>
  );
}
