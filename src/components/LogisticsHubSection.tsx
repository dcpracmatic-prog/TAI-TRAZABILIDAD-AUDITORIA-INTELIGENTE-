import { useState, type FormEvent } from 'react';
import { Compass, ExternalLink, MapPin, Navigation, Search } from 'lucide-react';
import type { GroundedPlace } from '../types/tai';

const PRESET_QUERIES = [
  'Centros logísticos industriales y depósitos en Dock Sud y Avellaneda, Buenos Aires',
  'Accesos portuarios y corredores logísticos entre Puerto de Buenos Aires y La Plata',
  'Parques industriales y centros de distribución en zona sur de Buenos Aires y Ezeiza',
];

export function LogisticsHubSection() {
  const [query, setQuery] = useState(PRESET_QUERIES[0]);
  const [coords, setCoords] = useState<{ latitude: number; longitude: number } | null>(null);
  const [geoStatus, setGeoStatus] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [resultText, setResultText] = useState('');
  const [places, setPlaces] = useState<GroundedPlace[]>([]);

  function handleUseGeolocation() {
    if (!navigator.geolocation) {
      setGeoStatus('Geolocalización no disponible en este navegador.');
      return;
    }
    setGeoStatus('Obteniendo ubicación...');
    navigator.geolocation.getCurrentPosition(
      (pos) => {
        setCoords({
          latitude: pos.coords.latitude,
          longitude: pos.coords.longitude,
        });
        setGeoStatus(
          `Ubicación detectada: ${pos.coords.latitude.toFixed(4)}, ${pos.coords.longitude.toFixed(4)}`
        );
      },
      () => {
        setGeoStatus('Permiso de ubicación denegado; usando referencia Dock Sud, Buenos Aires.');
      }
    );
  }

  async function runMapsGrounding(customQuery?: string) {
    const q = (customQuery ?? query).trim();
    if (!q) return;
    setLoading(true);
    setError('');
    try {
      const res = await fetch('/api/maps-grounding', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          query: q,
          latitude: coords?.latitude,
          longitude: coords?.longitude,
        }),
      });
      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.error || 'No se pudo consultar Google Maps Grounding.');
      }
      setResultText(data.text || '');
      setPlaces(Array.isArray(data.places) ? data.places : []);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Error de red al consultar ubicaciones.');
    } finally {
      setLoading(false);
    }
  }

  function handleSubmit(e: FormEvent) {
    e.preventDefault();
    runMapsGrounding();
  }

  return (
    <div className="space-y-6">
      {/* Hub Banner */}
      <div className="grid grid-cols-1 items-stretch gap-6 lg:grid-cols-12">
        <div className="relative overflow-hidden rounded-xl border border-slate-200 bg-slate-100 lg:col-span-7">
          <img
            src="/src/assets/images/buenos_aires_hub_1795283460099.jpg"
            alt="Centro Logístico Buenos Aires — Operaciones de embalaje, despacho y recepción"
            referrerPolicy="no-referrer"
            className="h-64 w-full object-cover lg:h-full"
          />
          <div className="absolute inset-x-0 bottom-0 bg-gradient-to-t from-slate-950/85 via-slate-950/45 to-transparent p-5 text-white">
            <p className="text-xs font-semibold">Alcance geográfico del piloto</p>
            <p className="mt-1 text-xs text-slate-200">
              Centro Logístico Buenos Aires · Embalaje, despacho, recepción y devolución controlada
            </p>
          </div>
        </div>

        <div className="rounded-xl border border-slate-200 bg-white p-6 lg:col-span-5">
          <div className="flex items-center justify-between border-b border-slate-100 pb-4">
            <div>
              <h2 className="font-display text-base font-semibold text-slate-900">
                Consulta geoespacial con Google Maps Grounding
              </h2>
              <p className="mt-1 text-xs text-slate-500">
                Información actualizada de centros logísticos y accesos vía Gemini + Google Maps.
              </p>
            </div>
            <Compass className="h-5 w-5 text-slate-400" />
          </div>

          <form onSubmit={handleSubmit} className="mt-4 space-y-3">
            <div>
              <label className="block text-xs font-medium text-slate-700">
                Consulta logística o zona en Argentina
              </label>
              <textarea
                rows={3}
                value={query}
                onChange={(e) => setQuery(e.target.value)}
                maxLength={350}
                className="mt-1 w-full rounded-lg border border-slate-200 px-3 py-2 text-xs text-slate-900 focus:border-sky-600 focus:outline-none"
              />
            </div>

            <div className="flex flex-wrap items-center gap-2">
              <button
                type="submit"
                disabled={loading}
                className="inline-flex items-center gap-1.5 rounded-lg bg-sky-700 px-4 py-2 text-xs font-semibold text-white hover:bg-sky-800 disabled:opacity-50"
              >
                <Search className="h-3.5 w-3.5" />
                {loading ? 'Consultando Maps...' : 'Consultar ubicaciones'}
              </button>
              <button
                type="button"
                onClick={handleUseGeolocation}
                className="inline-flex items-center gap-1.5 rounded-lg border border-slate-200 bg-white px-3 py-2 text-xs font-medium text-slate-700 hover:bg-slate-50"
              >
                <Navigation className="h-3.5 w-3.5" /> Usar mi ubicación
              </button>
            </div>

            {geoStatus && <p className="font-mono text-[11px] text-slate-500">{geoStatus}</p>}

            <div className="border-t border-slate-100 pt-3">
              <p className="text-[11px] font-medium text-slate-500">Consultas sugeridas:</p>
              <div className="mt-2 flex flex-col gap-1.5">
                {PRESET_QUERIES.map((preset) => (
                  <button
                    key={preset}
                    type="button"
                    onClick={() => {
                      setQuery(preset);
                      runMapsGrounding(preset);
                    }}
                    className="rounded-md border border-slate-200 bg-slate-50 px-2.5 py-1.5 text-left text-xs text-slate-700 transition-colors hover:border-sky-300 hover:bg-sky-50"
                  >
                    {preset}
                  </button>
                ))}
              </div>
            </div>
          </form>
        </div>
      </div>

      {/* Results & Mandatory Google Maps Grounding Links */}
      {error && (
        <div className="rounded-xl border border-red-200 bg-red-50 p-4 text-xs text-red-800">
          {error}
        </div>
      )}

      {(resultText || places.length > 0) && (
        <div className="grid grid-cols-1 gap-6 lg:grid-cols-12">
          <div className="rounded-xl border border-slate-200 bg-white p-6 lg:col-span-7">
            <h3 className="font-display text-sm font-semibold text-slate-900 border-b border-slate-100 pb-3">
              Análisis territorial y accesos logísticos
            </h3>
            <div className="mt-4 whitespace-pre-wrap text-xs leading-relaxed text-slate-700">
              {resultText}
            </div>
          </div>

          <div className="rounded-xl border border-slate-200 bg-white p-6 lg:col-span-5">
            <h3 className="font-display text-sm font-semibold text-slate-900 border-b border-slate-100 pb-3">
              Ubicaciones verificadas en Google Maps ({places.length})
            </h3>
            {places.length === 0 ? (
              <p className="mt-4 text-xs text-slate-500">
                No se devolvieron enlaces específicos de mapas para esta consulta.
              </p>
            ) : (
              <ul className="mt-4 space-y-3">
                {places.map((place, idx) => (
                  <li
                    key={`${place.uri}-${idx}`}
                    className="rounded-lg border border-slate-200 bg-slate-50/70 p-3 text-xs"
                  >
                    <a
                      href={place.uri}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="inline-flex items-center gap-1.5 font-semibold text-sky-700 hover:underline"
                    >
                      <MapPin className="h-3.5 w-3.5 shrink-0" />
                      <span>{place.title}</span>
                      <ExternalLink className="h-3 w-3 shrink-0" />
                    </a>

                    {place.reviewSnippets && place.reviewSnippets.length > 0 && (
                      <div className="mt-2 space-y-1 border-t border-slate-200 pt-2">
                        {place.reviewSnippets.map((snippet, sIdx) =>
                          snippet.uri ? (
                            <a
                              key={sIdx}
                              href={snippet.uri}
                              target="_blank"
                              rel="noopener noreferrer"
                              className="block text-[11px] text-slate-600 hover:text-sky-700 hover:underline"
                            >
                              {snippet.title || 'Ver reseña en Google Maps'}
                            </a>
                          ) : null
                        )}
                      </div>
                    )}
                  </li>
                ))}
              </ul>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
