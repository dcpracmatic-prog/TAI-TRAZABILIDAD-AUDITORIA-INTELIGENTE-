import { useState, type FormEvent } from 'react';
import {
  AlertTriangle,
  CheckCircle2,
  PackagePlus,
  Search,
  ShieldAlert,
} from 'lucide-react';
import type { IdentificationStatus, TaiPackage } from '../types/tai';
import { QrCodeDisplay } from './QrCodeDisplay';

interface PackagingSectionProps {
  packages: TaiPackage[];
  selectedPackageId: string | null;
  onSelectPackage: (id: string) => void;
  onCreatePackage: (input: {
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
  }) => Promise<void>;
  onValidateMaterial: (params: {
    pkg: TaiPackage;
    confirmedDescription: string;
    confirmedQuantity: number;
    validationNote: string;
  }) => Promise<void>;
  onLoadSample: () => Promise<void>;
  isAuthenticated: boolean;
  isBusy: boolean;
}

const LIFECYCLE_LABELS: Record<TaiPackage['lifecycleStatus'], string> = {
  packed: 'Empacado',
  in_transit: 'En tránsito',
  received: 'Recibido',
  return_open: 'Devolución abierta',
  conflict: 'En conflicto',
  audited: 'Auditado',
};

export function PackagingSection({
  packages,
  selectedPackageId,
  onSelectPackage,
  onCreatePackage,
  onValidateMaterial,
  onLoadSample,
  isAuthenticated,
  isBusy,
}: PackagingSectionProps) {
  const [code, setCode] = useState(`TAI-BA-${Math.floor(1000 + Math.random() * 9000)}`);
  const [fromArea, setFromArea] = useState('Almacén Central Dock Sud');
  const [targetArea, setTargetArea] = useState('Módulo Mantenimiento');
  const [zone, setZone] = useState('Zona Sur · Centro Logístico BA');
  const [contentSummary, setContentSummary] = useState('');
  const [quantity, setQuantity] = useState('10');
  const [unit, setUnit] = useState('unidades');
  const [identificationStatus, setIdentificationStatus] =
    useState<IdentificationStatus>('verified');
  const [observations, setObservations] = useState(
    'Cierre TAI integrado sobre solapas. Etiquetas visibles en diagonal exterior.'
  );
  const [operatorName, setOperatorName] = useState('Operador Embalaje BA');
  const [searchQuery, setSearchQuery] = useState('');
  const [filterStatus, setFilterStatus] = useState<'all' | 'verified' | 'uncertain_pending'>('all');
  const [formError, setFormError] = useState('');

  // Validation modal inline state for uncertain materials
  const [validatingPkg, setValidatingPkg] = useState<TaiPackage | null>(null);
  const [confirmedDesc, setConfirmedDesc] = useState('');
  const [confirmedQty, setConfirmedQty] = useState('1');
  const [validationNote, setValidationNote] = useState('');

  const filtered = packages.filter((pkg) => {
    const matchesFilter =
      filterStatus === 'all' || pkg.identificationStatus === filterStatus;
    const q = searchQuery.trim().toLowerCase();
    const matchesSearch =
      !q ||
      pkg.code.toLowerCase().includes(q) ||
      pkg.contentSummary.toLowerCase().includes(q) ||
      pkg.fromArea.toLowerCase().includes(q) ||
      pkg.targetArea.toLowerCase().includes(q);
    return matchesFilter && matchesSearch;
  });

  const selectedPkg =
    packages.find((p) => p.id === selectedPackageId) || filtered[0] || null;

  async function handleSubmit(e: FormEvent) {
    e.preventDefault();
    setFormError('');
    if (!contentSummary.trim()) {
      setFormError('Describe el contenido verificado o marca el material como pendiente/incierto.');
      return;
    }
    await onCreatePackage({
      code: code.trim(),
      fromArea: fromArea.trim(),
      targetArea: targetArea.trim(),
      zone: zone.trim(),
      contentSummary: contentSummary.trim(),
      quantity: Number(quantity) || 0,
      unit: unit.trim() || 'unidades',
      identificationStatus,
      observations: observations.trim(),
      operatorName: operatorName.trim(),
    });
    setCode(`TAI-BA-${Math.floor(1000 + Math.random() * 9000)}`);
    setContentSummary('');
  }

  async function handleConfirmMaterial(e: FormEvent) {
    e.preventDefault();
    if (!validatingPkg) return;
    await onValidateMaterial({
      pkg: validatingPkg,
      confirmedDescription: confirmedDesc.trim(),
      confirmedQuantity: Number(confirmedQty) || 0,
      validationNote: validationNote.trim() || 'Validado por supervisor técnico YPF.',
    });
    setValidatingPkg(null);
  }

  return (
    <div className="grid grid-cols-1 gap-6 lg:grid-cols-12">
      {/* Left: Create Package Form */}
      <div className="rounded-xl border border-slate-200 bg-white p-6 lg:col-span-5">
        <div className="flex items-center justify-between border-b border-slate-100 pb-4">
          <div>
            <h2 className="font-display text-base font-semibold text-slate-900">
              Embalaje y generación de QR TAI
            </h2>
            <p className="mt-1 text-xs text-slate-500">
              El QR identifica el registro; nunca contiene claves ni credenciales.
            </p>
          </div>
          <PackagePlus className="h-5 w-5 text-slate-400" />
        </div>

        <form onSubmit={handleSubmit} className="mt-4 space-y-3.5">
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="block text-xs font-medium text-slate-700">Código de caja</label>
              <input
                type="text"
                value={code}
                onChange={(e) => setCode(e.target.value)}
                maxLength={64}
                required
                className="mt-1 w-full rounded-lg border border-slate-200 px-3 py-2 font-mono text-xs text-slate-900 focus:border-sky-600 focus:outline-none"
              />
            </div>
            <div>
              <label className="block text-xs font-medium text-slate-700">Operador embalaje</label>
              <input
                type="text"
                value={operatorName}
                onChange={(e) => setOperatorName(e.target.value)}
                maxLength={120}
                required
                className="mt-1 w-full rounded-lg border border-slate-200 px-3 py-2 text-xs text-slate-900 focus:border-sky-600 focus:outline-none"
              />
            </div>
          </div>

          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="block text-xs font-medium text-slate-700">FROM (Origen)</label>
              <input
                type="text"
                value={fromArea}
                onChange={(e) => setFromArea(e.target.value)}
                maxLength={120}
                required
                className="mt-1 w-full rounded-lg border border-slate-200 px-3 py-2 text-xs text-slate-900 focus:border-sky-600 focus:outline-none"
              />
            </div>
            <div>
              <label className="block text-xs font-medium text-slate-700">Área / Módulo destino</label>
              <input
                type="text"
                value={targetArea}
                onChange={(e) => setTargetArea(e.target.value)}
                maxLength={120}
                required
                className="mt-1 w-full rounded-lg border border-slate-200 px-3 py-2 text-xs text-slate-900 focus:border-sky-600 focus:outline-none"
              />
            </div>
          </div>

          <div>
            <label className="block text-xs font-medium text-slate-700">
              Zona / Sector (Centro Logístico Buenos Aires)
            </label>
            <input
              type="text"
              value={zone}
              onChange={(e) => setZone(e.target.value)}
              maxLength={120}
              required
              className="mt-1 w-full rounded-lg border border-slate-200 px-3 py-2 text-xs text-slate-900 focus:border-sky-600 focus:outline-none"
            />
          </div>

          <div>
            <label className="block text-xs font-medium text-slate-700">
              Contenido verificado (o descripción preliminar)
            </label>
            <input
              type="text"
              value={contentSummary}
              onChange={(e) => setContentSummary(e.target.value)}
              maxLength={300}
              placeholder="Ej. Bridas ASTM A105 4'' o Repuesto sin etiqueta SAP"
              required
              className="mt-1 w-full rounded-lg border border-slate-200 px-3 py-2 text-xs text-slate-900 focus:border-sky-600 focus:outline-none"
            />
          </div>

          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="block text-xs font-medium text-slate-700">Cantidad</label>
              <input
                type="number"
                min={0}
                max={1000000}
                value={quantity}
                onChange={(e) => setQuantity(e.target.value)}
                required
                className="mt-1 w-full rounded-lg border border-slate-200 px-3 py-2 font-mono text-xs text-slate-900 focus:border-sky-600 focus:outline-none"
              />
            </div>
            <div>
              <label className="block text-xs font-medium text-slate-700">Unidad</label>
              <input
                type="text"
                value={unit}
                onChange={(e) => setUnit(e.target.value)}
                maxLength={40}
                required
                className="mt-1 w-full rounded-lg border border-slate-200 px-3 py-2 text-xs text-slate-900 focus:border-sky-600 focus:outline-none"
              />
            </div>
          </div>

          <div>
            <label className="block text-xs font-medium text-slate-700">
              Estado de identificación del material
            </label>
            <div className="mt-1.5 grid grid-cols-2 gap-2 rounded-lg bg-slate-100 p-1">
              <button
                type="button"
                onClick={() => setIdentificationStatus('verified')}
                className={`rounded-md px-3 py-1.5 text-xs font-medium transition-colors ${
                  identificationStatus === 'verified'
                    ? 'bg-white text-slate-900 shadow-sm'
                    : 'text-slate-600 hover:text-slate-900'
                }`}
              >
                Verificado con certeza
              </button>
              <button
                type="button"
                onClick={() => setIdentificationStatus('uncertain_pending')}
                className={`rounded-md px-3 py-1.5 text-xs font-medium transition-colors ${
                  identificationStatus === 'uncertain_pending'
                    ? 'bg-white text-amber-800 shadow-sm'
                    : 'text-slate-600 hover:text-slate-900'
                }`}
              >
                Pendiente / Incierto
              </button>
            </div>
            {identificationStatus === 'uncertain_pending' && (
              <p className="mt-1.5 text-[11px] text-amber-800">
                Regla TAI: no se convierte una conjetura en identificación confirmada; requerirá validación posterior.
              </p>
            )}
          </div>

          <div>
            <label className="block text-xs font-medium text-slate-700">Observaciones en bitácora</label>
            <textarea
              rows={2}
              value={observations}
              onChange={(e) => setObservations(e.target.value)}
              maxLength={500}
              className="mt-1 w-full rounded-lg border border-slate-200 px-3 py-2 text-xs text-slate-900 focus:border-sky-600 focus:outline-none"
            />
          </div>

          {formError && <p className="text-xs font-medium text-red-600">{formError}</p>}

          <button
            type="submit"
            disabled={!isAuthenticated || isBusy}
            className="w-full rounded-lg bg-sky-700 px-4 py-2.5 text-xs font-semibold text-white transition-colors hover:bg-sky-800 disabled:opacity-50"
          >
            {isBusy ? 'Sellando registro...' : isAuthenticated ? 'Empacar y emitir QR TAI' : 'Conecta Google para registrar'}
          </button>
        </form>
      </div>

      {/* Right: Package List + Selected Physical/Digital Card */}
      <div className="space-y-6 lg:col-span-7">
        <div className="rounded-xl border border-slate-200 bg-white p-6">
          <div className="flex flex-wrap items-center justify-between gap-3 border-b border-slate-100 pb-4">
            <h2 className="font-display text-base font-semibold text-slate-900">
              Unidades logísticas registradas ({filtered.length})
            </h2>
            <div className="flex flex-wrap items-center gap-2">
              <div className="relative">
                <Search className="pointer-events-none absolute left-2.5 top-2 h-3.5 w-3.5 text-slate-400" />
                <input
                  type="text"
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  placeholder="Buscar código o área..."
                  className="rounded-lg border border-slate-200 py-1.5 pl-8 pr-3 text-xs text-slate-800 focus:border-sky-600 focus:outline-none"
                />
              </div>
              <div className="flex items-center gap-1 rounded-lg bg-slate-100 p-1">
                {(['all', 'verified', 'uncertain_pending'] as const).map((tab) => (
                  <button
                    key={tab}
                    type="button"
                    onClick={() => setFilterStatus(tab)}
                    className={`rounded-md px-2.5 py-1 text-xs font-medium transition-colors whitespace-nowrap ${
                      filterStatus === tab
                        ? 'bg-white text-slate-900 shadow-sm'
                        : 'text-slate-600 hover:text-slate-900'
                    }`}
                  >
                    {tab === 'all' ? 'Todos' : tab === 'verified' ? 'Verificados' : 'Pendientes'}
                  </button>
                ))}
              </div>
            </div>
          </div>

          {filtered.length === 0 ? (
            <div className="py-10 text-center">
              <p className="text-sm font-medium text-slate-700">
                No hay unidades logísticas registradas en este filtro.
              </p>
              <p className="mt-1 text-xs text-slate-500">
                Registra una caja nueva en el formulario lateral o carga el escenario piloto de Buenos Aires.
              </p>
              {isAuthenticated && packages.length === 0 && (
                <button
                  type="button"
                  disabled={isBusy}
                  onClick={onLoadSample}
                  className="mt-4 rounded-lg border border-sky-200 bg-sky-50 px-4 py-2 text-xs font-semibold text-sky-800 hover:bg-sky-100 disabled:opacity-50"
                >
                  Cargar escenario piloto YPF
                </button>
              )}
            </div>
          ) : (
            <div className="mt-4 overflow-x-auto">
              <table className="w-full text-left text-xs">
                <thead>
                  <tr className="border-b border-slate-200 text-slate-500">
                    <th className="py-2 pr-3 font-medium">Código</th>
                    <th className="py-2 pr-3 font-medium">Origen / Destino</th>
                    <th className="py-2 pr-3 font-medium">Identificación</th>
                    <th className="py-2 pr-3 font-medium text-right">Cant.</th>
                    <th className="py-2 font-medium">Estado</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-100">
                  {filtered.map((pkg) => {
                    const isSelected = selectedPkg?.id === pkg.id;
                    return (
                      <tr
                        key={pkg.id}
                        onClick={() => onSelectPackage(pkg.id)}
                        className={`cursor-pointer transition-colors ${
                          isSelected ? 'bg-sky-50/70' : 'hover:bg-slate-50'
                        }`}
                      >
                        <td className="py-2.5 pr-3 font-mono font-semibold text-slate-900">
                          {pkg.code}
                        </td>
                        <td className="py-2.5 pr-3 text-slate-700">
                          <span className="font-medium">{pkg.fromArea}</span>
                          <span className="mx-1 text-slate-400">→</span>
                          <span>{pkg.targetArea}</span>
                        </td>
                        <td className="py-2.5 pr-3">
                          {pkg.identificationStatus === 'verified' ? (
                            <span className="inline-flex items-center gap-1 font-medium text-emerald-700">
                              <CheckCircle2 className="h-3.5 w-3.5" /> Verificado
                            </span>
                          ) : (
                            <span className="inline-flex items-center gap-1 font-medium text-amber-700">
                              <AlertTriangle className="h-3.5 w-3.5" /> Incierto
                            </span>
                          )}
                        </td>
                        <td className="py-2.5 pr-3 text-right font-mono tabular-nums text-slate-800">
                          {pkg.quantity} {pkg.unit}
                        </td>
                        <td className="py-2.5 text-slate-700">
                          {LIFECYCLE_LABELS[pkg.lifecycleStatus]}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}
        </div>

        {/* Selected Package Physical Label + QR Preview */}
        {selectedPkg && (
          <div className="rounded-xl border border-slate-200 bg-white p-6">
            <div className="flex flex-wrap items-start justify-between gap-4 border-b border-slate-100 pb-4">
              <div>
                <p className="font-mono text-xs text-slate-500">
                  {selectedPkg.id} · {selectedPkg.zone}
                </p>
                <h3 className="mt-1 font-display text-lg font-bold text-slate-900">
                  Etiqueta física-digital TAI — {selectedPkg.code}
                </h3>
              </div>

              {selectedPkg.identificationStatus === 'uncertain_pending' && (
                <button
                  type="button"
                  onClick={() => {
                    setValidatingPkg(selectedPkg);
                    setConfirmedDesc(selectedPkg.contentSummary);
                    setConfirmedQty(String(selectedPkg.quantity));
                    setValidationNote('');
                  }}
                  className="inline-flex items-center gap-1.5 rounded-lg border border-amber-300 bg-amber-50 px-3 py-1.5 text-xs font-semibold text-amber-900 hover:bg-amber-100"
                >
                  <ShieldAlert className="h-3.5 w-3.5" />
                  Validar material pendiente
                </button>
              )}
            </div>

            <div className="mt-5 grid grid-cols-1 gap-6 md:grid-cols-12">
              <div className="md:col-span-4">
                <QrCodeDisplay
                  value={selectedPkg.qrPayload}
                  label="Cara A · QR del paquete"
                  caption={selectedPkg.qrPayload}
                />
              </div>

              <div className="space-y-3 rounded-lg border border-slate-200 bg-slate-50 p-4 md:col-span-8">
                <p className="text-xs font-semibold text-slate-800">
                  Cara B · Bitácora visible en cierre de cartón
                </p>
                <dl className="grid grid-cols-1 gap-2 text-xs sm:grid-cols-2">
                  <div>
                    <dt className="text-slate-500">FROM (Origen)</dt>
                    <dd className="font-medium text-slate-900">{selectedPkg.fromArea}</dd>
                  </div>
                  <div>
                    <dt className="text-slate-500">Receptor / Área o Módulo</dt>
                    <dd className="font-medium text-slate-900">{selectedPkg.targetArea}</dd>
                  </div>
                  <div>
                    <dt className="text-slate-500">Contenido y cantidad</dt>
                    <dd className="font-medium text-slate-900">
                      {selectedPkg.contentSummary} ({selectedPkg.quantity} {selectedPkg.unit})
                    </dd>
                  </div>
                  <div>
                    <dt className="text-slate-500">Estado de cierre / eventos</dt>
                    <dd className="font-mono text-slate-900 tabular-nums">
                      {selectedPkg.sealStatus} · {selectedPkg.eventCount} evento(s)
                    </dd>
                  </div>
                </dl>
                <div className="border-t border-slate-200 pt-2 text-xs">
                  <span className="text-slate-500">Observaciones: </span>
                  <span className="text-slate-800">{selectedPkg.observations || 'Sin observaciones'}</span>
                </div>
              </div>
            </div>

            {validatingPkg && validatingPkg.id === selectedPkg.id && (
              <form
                onSubmit={handleConfirmMaterial}
                className="mt-5 space-y-3 rounded-lg border border-amber-200 bg-amber-50/60 p-4"
              >
                <p className="text-xs font-semibold text-amber-950">
                  Validación técnica de material pendiente ({validatingPkg.code})
                </p>
                <div className="grid grid-cols-1 gap-3 sm:grid-cols-3">
                  <div className="sm:col-span-2">
                    <label className="block text-[11px] font-medium text-slate-700">
                      Descripción y código confirmado
                    </label>
                    <input
                      type="text"
                      value={confirmedDesc}
                      onChange={(e) => setConfirmedDesc(e.target.value)}
                      required
                      maxLength={300}
                      className="mt-1 w-full rounded-md border border-slate-200 bg-white px-2.5 py-1.5 text-xs"
                    />
                  </div>
                  <div>
                    <label className="block text-[11px] font-medium text-slate-700">
                      Cantidad confirmada
                    </label>
                    <input
                      type="number"
                      min={0}
                      value={confirmedQty}
                      onChange={(e) => setConfirmedQty(e.target.value)}
                      required
                      className="mt-1 w-full rounded-md border border-slate-200 bg-white px-2.5 py-1.5 font-mono text-xs"
                    />
                  </div>
                </div>
                <div>
                  <label className="block text-[11px] font-medium text-slate-700">
                    Nota de validación (YPF / Supervisor)
                  </label>
                  <input
                    type="text"
                    value={validationNote}
                    onChange={(e) => setValidationNote(e.target.value)}
                    placeholder="Ej. Código SAP confirmado en inspección física."
                    maxLength={500}
                    className="mt-1 w-full rounded-md border border-slate-200 bg-white px-2.5 py-1.5 text-xs"
                  />
                </div>
                <div className="flex justify-end gap-2">
                  <button
                    type="button"
                    onClick={() => setValidatingPkg(null)}
                    className="rounded-md border border-slate-200 bg-white px-3 py-1.5 text-xs font-medium text-slate-700"
                  >
                    Cancelar
                  </button>
                  <button
                    type="submit"
                    disabled={isBusy}
                    className="rounded-md bg-amber-700 px-3 py-1.5 text-xs font-semibold text-white hover:bg-amber-800"
                  >
                    Confirmar identificación
                  </button>
                </div>
              </form>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
