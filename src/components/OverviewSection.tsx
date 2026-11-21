import { useEffect, useState, type FormEvent } from 'react';
import {
  CheckCircle2,
  ExternalLink,
  Layers,
  PackageCheck,
  QrCode,
  Save,
  ShieldCheck,
} from 'lucide-react';
import type { AuditLog, OfflinePendingEvent, PilotConfig, TaiPackage } from '../types/tai';

interface OverviewSectionProps {
  packages: TaiPackage[];
  auditLogs: AuditLog[];
  offlineQueue: OfflinePendingEvent[];
  pilotConfig: PilotConfig | null;
  onSavePilotConfig: (input: Omit<PilotConfig, 'ownerId' | 'updatedAt'>) => Promise<void>;
  onNavigate: (tab: 'overview' | 'packaging' | 'transfers' | 'audit' | 'hub') => void;
  onLoadSample: () => Promise<void>;
  isBusy: boolean;
  isAuthenticated: boolean;
}

const ASSEMBLY_STEPS = [
  {
    step: '01',
    title: 'Plegado de solapas laterales',
    detail:
      'Se cierran primero las solapas izquierda y derecha de la caja formando los triángulos estructurales de apoyo.',
  },
  {
    step: '02',
    title: 'Adhesión e inserción del TAI',
    detail:
      'Se aplica pegamento en las superficies de contacto y se posiciona la pieza de cartón TAI integrada al cierre.',
  },
  {
    step: '03',
    title: 'Cierre diagonal exterior',
    detail:
      'Se cierran las solapas superior e inferior integrando el TAI. Las etiquetas de instrucciones quedan visibles sobre la diagonal exterior.',
  },
  {
    step: '04',
    title: 'Doble cara física-digital',
    detail:
      'Una cara porta el QR identificador del registro (sin claves ni contenido completo); la otra cara registra FROM, fecha, observaciones, receptor y área.',
  },
];

export function OverviewSection({
  packages,
  auditLogs,
  offlineQueue,
  pilotConfig,
  onSavePilotConfig,
  onNavigate,
  onLoadSample,
  isBusy,
  isAuthenticated,
}: OverviewSectionProps) {
  const [solverOrg, setSolverOrg] = useState(
    pilotConfig?.solverOrg || 'Organización Postulante TAI (Por confirmar)'
  );
  const [boxSupplier, setBoxSupplier] = useState(
    pilotConfig?.boxSupplier || 'Proveedor de maquila de cajas participante (Por confirmar)'
  );
  const [trlLevel, setTrlLevel] = useState(pilotConfig?.trlLevel || 'TRL 4–5 (Maqueta validada)');
  const [pilotFacility, setPilotFacility] = useState(
    pilotConfig?.pilotFacility || 'Centro Logístico Buenos Aires — YPF'
  );
  const [saving, setSaving] = useState(false);
  const [savedBanner, setSavedBanner] = useState(false);

  useEffect(() => {
    if (pilotConfig) {
      if (pilotConfig.solverOrg) setSolverOrg(pilotConfig.solverOrg);
      if (pilotConfig.boxSupplier) setBoxSupplier(pilotConfig.boxSupplier);
      if (pilotConfig.trlLevel) setTrlLevel(pilotConfig.trlLevel);
      if (pilotConfig.pilotFacility) setPilotFacility(pilotConfig.pilotFacility);
    }
  }, [pilotConfig]);

  const totalPackages = packages.length;
  const verifiedCount = packages.filter((p) => p.identificationStatus === 'verified').length;
  const conflictCount = packages.filter((p) => p.lifecycleStatus === 'conflict').length;
  const csgInvalidations = auditLogs.filter((l) => l.action === 'csg_tamper_invalidated').length;
  const completenessPct =
    totalPackages > 0 ? Math.round((verifiedCount / totalPackages) * 100) : 0;

  async function handleSaveConfig(e: FormEvent) {
    e.preventDefault();
    if (!isAuthenticated) return;
    setSaving(true);
    setSavedBanner(false);
    try {
      await onSavePilotConfig({
        solverOrg,
        boxSupplier,
        trlLevel,
        pilotFacility,
        spreadsheetId: pilotConfig?.spreadsheetId || '',
        spreadsheetTitle: pilotConfig?.spreadsheetTitle || '',
      });
      setSavedBanner(true);
    } finally {
      setSaving(false);
    }
  }

  return (
    <div className="space-y-8">
      {/* Hero Split */}
      <section className="grid grid-cols-1 items-stretch gap-6 lg:grid-cols-12">
        <div className="flex flex-col justify-between rounded-xl border border-slate-200 bg-white p-6 lg:col-span-7 lg:p-8">
          <div>
            <p className="text-xs font-medium text-sky-700">
              Propuesta Reto YPF · Innocentive · Centro Logístico Buenos Aires
            </p>
            <h1 className="mt-2 font-display text-2xl font-bold tracking-tight text-slate-900 [text-wrap:balance] sm:text-3xl">
              Trazabilidad físico-digital de cierre y transferencias sin reemplazar SAP MM, Infor WMS ni Unigis TMS
            </h1>
            <p className="mt-3 max-w-2xl text-sm leading-relaxed text-slate-600">
              TAI vincula el cierre físico de cartón de cada unidad logística con un QR identificador, una bitácora visible y un comprobante de validación (CVV) sellado mediante AES-256-GCM y CSG, capaz de operar sin conectividad continua.
            </p>
          </div>

          <div className="mt-6 flex flex-wrap items-center gap-3 pt-4 border-t border-slate-100">
            <button
              type="button"
              onClick={() => onNavigate('packaging')}
              className="inline-flex items-center gap-2 rounded-lg bg-sky-700 px-4 py-2 text-xs font-semibold text-white transition-colors hover:bg-sky-800 whitespace-nowrap shrink-0"
            >
              <QrCode className="h-4 w-4" />
              Registrar unidad TAI
            </button>
            <button
              type="button"
              onClick={() => onNavigate('transfers')}
              className="inline-flex items-center gap-2 rounded-lg border border-slate-200 bg-white px-4 py-2 text-xs font-semibold text-slate-700 transition-colors hover:bg-slate-50 whitespace-nowrap shrink-0"
            >
              <PackageCheck className="h-4 w-4" />
              Transferencia y modo offline
            </button>
            {isAuthenticated && totalPackages === 0 && (
              <button
                type="button"
                disabled={isBusy}
                onClick={onLoadSample}
                className="inline-flex items-center gap-2 rounded-lg border border-sky-200 bg-sky-50 px-4 py-2 text-xs font-semibold text-sky-800 transition-colors hover:bg-sky-100 disabled:opacity-50 whitespace-nowrap shrink-0"
              >
                Cargar escenario piloto YPF
              </button>
            )}
          </div>
        </div>

        <div className="relative overflow-hidden rounded-xl border border-slate-200 bg-slate-100 lg:col-span-5">
          <img
            src="/src/assets/images/tai_box_seal_1795283459353.jpg"
            alt="Cierre físico TAI integrado en caja de cartón corrugado con código QR y bitácora"
            referrerPolicy="no-referrer"
            className="h-64 w-full object-cover lg:h-full"
          />
          <div className="absolute inset-x-0 bottom-0 bg-gradient-to-t from-slate-950/85 via-slate-950/45 to-transparent p-5 text-white">
            <p className="text-xs font-semibold">Mecanismo físico-digital TAI</p>
            <p className="mt-1 text-xs text-slate-200">
              Cierre triangular diagonal integrado al embalaje · QR de referencia · Bitácora visible en cara externa
            </p>
          </div>
        </div>
      </section>

      {/* 4-Column Live Pilot KPI Strip */}
      <section className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <div className="rounded-xl border border-slate-200 bg-white p-5">
          <p className="text-xs font-medium text-slate-500">Unidades TAI registradas</p>
          <p className="mt-2 font-mono text-2xl font-semibold text-slate-900 tabular-nums">
            {totalPackages}
          </p>
          <p className="mt-1 text-xs text-slate-500">
            {verifiedCount} identificadas · {totalPackages - verifiedCount} pendientes
          </p>
        </div>

        <div className="rounded-xl border border-slate-200 bg-white p-5">
          <p className="text-xs font-medium text-slate-500">Completitud de identificación</p>
          <p className="mt-2 font-mono text-2xl font-semibold text-slate-900 tabular-nums">
            {completenessPct}%
          </p>
          <p className="mt-1 text-xs text-slate-500">
            Materiales inciertos bloqueados hasta validación
          </p>
        </div>

        <div className="rounded-xl border border-slate-200 bg-white p-5">
          <p className="text-xs font-medium text-slate-500">Eventos en cola offline</p>
          <p className="mt-2 font-mono text-2xl font-semibold text-slate-900 tabular-nums">
            {offlineQueue.length}
          </p>
          <p className="mt-1 text-xs text-slate-500">
            {conflictCount} paquete(s) en conflicto de secuencia
          </p>
        </div>

        <div className="rounded-xl border border-slate-200 bg-white p-5">
          <p className="text-xs font-medium text-slate-500">Registros maestros de auditoría</p>
          <p className="mt-2 font-mono text-2xl font-semibold text-slate-900 tabular-nums">
            {auditLogs.length}
          </p>
          <p className="mt-1 text-xs text-slate-500">
            {csgInvalidations} invalidación(es) CSG documentadas
          </p>
        </div>
      </section>

      {/* Physical Assembly Guide + Solver Dossier */}
      <section className="grid grid-cols-1 gap-6 lg:grid-cols-12">
        <div className="rounded-xl border border-slate-200 bg-white p-6 lg:col-span-7">
          <div className="flex items-center justify-between gap-4 border-b border-slate-100 pb-4">
            <div>
              <h2 className="font-display text-base font-semibold text-slate-900">
                01. Procedimiento de maquila e integración física del cierre TAI
              </h2>
              <p className="mt-1 text-xs text-slate-500">
                Diseño conceptual: Arturo Balderas · Adaptación sobre el proveedor actual de cajas sin montar planta nueva
              </p>
            </div>
            <Layers className="h-5 w-5 shrink-0 text-slate-400" />
          </div>

          <div className="mt-5 grid grid-cols-1 gap-4 sm:grid-cols-2">
            {ASSEMBLY_STEPS.map((item) => (
              <div key={item.step} className="rounded-lg border border-slate-200 bg-slate-50/70 p-4">
                <p className="font-mono text-xs font-semibold text-sky-700">Paso {item.step}</p>
                <h3 className="mt-1 text-sm font-semibold text-slate-900">{item.title}</h3>
                <p className="mt-1.5 text-xs leading-relaxed text-slate-600">{item.detail}</p>
              </div>
            ))}
          </div>

          <div className="mt-5 flex flex-wrap items-center gap-4 border-t border-slate-100 pt-4 text-xs text-slate-600">
            <a
              href="https://www.innocentive.com/challenges/intelligent-materials-traceability-and-logistics/"
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex items-center gap-1 font-medium text-sky-700 hover:underline"
            >
              Reto Innocentive YPF <ExternalLink className="h-3 w-3" />
            </a>
            <a
              href="https://github.com/dcpracmatic-prog/CSG"
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex items-center gap-1 font-medium text-sky-700 hover:underline"
            >
              Repositorio CSG <ExternalLink className="h-3 w-3" />
            </a>
            <a
              href="https://www.gs1.org/standards/epcis"
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex items-center gap-1 font-medium text-sky-700 hover:underline"
            >
              Referencia GS1 EPCIS <ExternalLink className="h-3 w-3" />
            </a>
          </div>
        </div>

        {/* Solver Dossier Form */}
        <div className="rounded-xl border border-slate-200 bg-white p-6 lg:col-span-5">
          <div className="flex items-center justify-between gap-4 border-b border-slate-100 pb-4">
            <div>
              <h2 className="font-display text-base font-semibold text-slate-900">
                02. Ficha técnica del Solver y alcance
              </h2>
              <p className="mt-1 text-xs text-slate-500">
                Responsable del diseño de TAI: Arturo Balderas
              </p>
            </div>
            <ShieldCheck className="h-5 w-5 shrink-0 text-slate-400" />
          </div>

          <form onSubmit={handleSaveConfig} className="mt-4 space-y-3.5">
            <div>
              <label className="block text-xs font-medium text-slate-700">
                Solver (razón social postulante)
              </label>
              <input
                type="text"
                value={solverOrg}
                onChange={(e) => setSolverOrg(e.target.value)}
                maxLength={160}
                className="mt-1 w-full rounded-lg border border-slate-200 px-3 py-2 text-xs text-slate-900 focus:border-sky-600 focus:outline-none"
              />
            </div>

            <div>
              <label className="block text-xs font-medium text-slate-700">
                Proveedor de maquila de cajas
              </label>
              <input
                type="text"
                value={boxSupplier}
                onChange={(e) => setBoxSupplier(e.target.value)}
                maxLength={160}
                className="mt-1 w-full rounded-lg border border-slate-200 px-3 py-2 text-xs text-slate-900 focus:border-sky-600 focus:outline-none"
              />
            </div>

            <div>
              <label className="block text-xs font-medium text-slate-700">
                Nivel de madurez tecnológica (TRL)
              </label>
              <input
                type="text"
                value={trlLevel}
                onChange={(e) => setTrlLevel(e.target.value)}
                maxLength={64}
                className="mt-1 w-full rounded-lg border border-slate-200 px-3 py-2 text-xs text-slate-900 focus:border-sky-600 focus:outline-none"
              />
            </div>

            <div>
              <label className="block text-xs font-medium text-slate-700">
                Instalación del piloto
              </label>
              <input
                type="text"
                value={pilotFacility}
                onChange={(e) => setPilotFacility(e.target.value)}
                maxLength={160}
                className="mt-1 w-full rounded-lg border border-slate-200 px-3 py-2 text-xs text-slate-900 focus:border-sky-600 focus:outline-none"
              />
            </div>

            {savedBanner && (
              <p className="flex items-center gap-1.5 text-xs font-medium text-emerald-700">
                <CheckCircle2 className="h-4 w-4" />
                Ficha del piloto guardada en Firestore.
              </p>
            )}

            <button
              type="submit"
              disabled={!isAuthenticated || saving}
              className="inline-flex w-full items-center justify-center gap-2 rounded-lg bg-slate-900 px-4 py-2 text-xs font-semibold text-white transition-colors hover:bg-slate-800 disabled:opacity-50"
            >
              <Save className="h-3.5 w-3.5" />
              {saving ? 'Guardando...' : isAuthenticated ? 'Guardar ficha del piloto' : 'Inicia sesión para guardar'}
            </button>
          </form>
        </div>
      </section>
    </div>
  );
}
