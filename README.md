[![TAI CI](https://github.com/dcpracmatic-prog/TAI-TRAZABILIDAD-AUDITORIA-INTELIGENTE-/actions/workflows/ci.yml/badge.svg)](https://github.com/dcpracmatic-prog/TAI-TRAZABILIDAD-AUDITORIA-INTELIGENTE-/actions/workflows/ci.yml)

# TAI — Trazabilidad y Auditoría Inteligente

Plataforma piloto físico-digital para trazar unidades logísticas de punta a punta: embalaje con sello y código QR, transferencias entre áreas con aceptación firmada por el receptor, operación sin conexión y auditoría criptográfica con bitácora exportable a Google Sheets.

Desarrollada como piloto para el reto YPF. La interfaz está en español.

## Qué resuelve

Una unidad logística (caja, kit, pallet) recibe un identificador y un **CVV** (certificado de validez verificable) en cada evento de su recorrido. Cada evento queda sellado y encadenado, de modo que cualquier alteración posterior es detectable y el documento puede invalidarse sin destruir la evidencia.

El flujo cubre:

1. **Embalaje** — se crea el paquete, se genera el QR `tai://pkg/<id>` (el QR sólo contiene la referencia, nunca el contenido) y se emite el evento `pack`.
2. **Transferencias** — despacho, recepción y devolución. La recepción exige una **QR de aceptación** firmada por el receptor (ECDSA P-256) y verifica que el paquete no haya sido abierto o dañado.
3. **Operación offline** — el sellado y la aceptación funcionan sin conexión. Los eventos se guardan cifrados en el dispositivo y se sincronizan luego, con control de duplicados.
4. **Auditoría CSG** — verificación de integridad de cada CVV, invalidación de documentos alterados (`invalidated_csg`) y registro en una bitácora maestra inmutable.
5. **Google Sheets** — creación de una planilla con las pestañas `Paquetes`, `Eventos_CVV` y `Auditoria_Maestra`, y sincronización de la bitácora.
6. **Centro Logístico** — consulta de ubicaciones, accesos viales y zonas industriales con Gemini y Google Maps grounding.

### Módulos de la interfaz

| Pestaña | Función |
|---|---|
| Resumen | Estado general del piloto, configuración (organización, proveedor de cajas, TRL, planta, planilla vinculada), guía de armado de la caja TAI y carga de un escenario base de demostración. |
| Embalaje y QR | Alta de paquetes y generación del QR de cada unidad. |
| Transferencias | Despacho, recepción y devolución; escaneo de QR de aceptación; validación de material en casos inciertos. |
| Auditoría CSG | Verificación de CVV, invalidación por CSG, creación de la planilla y registro de sincronizaciones. |
| Centro Logístico | Consultas geográficas con Gemini + Google Maps. |

## Arquitectura

```
┌──────────────────────────── Navegador ────────────────────────────┐
│ React 19 + Vite + Tailwind 4                                      │
│  ├─ Sellado y verificación CVV locales (AES-256-GCM + HMAC)       │
│  ├─ Firmas ECDSA P-256 (aceptación y sello de estación)           │
│  ├─ Cola offline cifrada (IndexedDB, PBKDF2-SHA256 310 000 iter.) │
│  ├─ Exportador de estación offline (HTML protegido) y lotes .json │
│  └─ Sincronización Firestore (persistentLocalCache)               │
└──────────┬───────────────────────────┬──────────────────┬─────────┘
           │ Firebase Auth (Google)    │ Firestore        │ Sheets API / Drive
           ▼                           ▼                  ▼
   useful-cyclist-…            colecciones:          planilla del piloto
                               packages/{id}/events,
                               auditLogs, pilotConfigs
           │
           │ /api/*  (Express, server.ts, puerto 3000)
           ▼
   /api/crypto/verify       verificación de respaldo (AES-GCM + CSG)
   /api/crypto/seal         sellado en servidor (ver "Limitaciones")
   /api/maps-grounding      Gemini + Google Maps grounding
   /api/health
```

- **Frontend:** `src/` — React 19, Vite 8, Tailwind CSS 4, lucide-react, motion, html5-qrcode / jsqr / react-qr-scanner para el escaneo de QR.
- **Backend:** `server.ts` — Express 4. En desarrollo monta Vite como middleware; en producción sirve `dist/`.
- **Datos:** Firebase Authentication (Google) y Cloud Firestore. Reglas en `firestore.rules`.
- **IA:** `@google/genai`, usada sólo desde el servidor para `/api/maps-grounding`.
- **Integraciones:** Google Sheets API v4 y Google Drive (selector de archivos) con scopes `spreadsheets`, `drive.file` y `drive.metadata.readonly`.

### Modelo de datos (Firestore)

| Colección | Documento | Notas |
|---|---|---|
| `packages/{packageId}` | `TaiPackage` | `ownerId` = UID del operador. Estado de ciclo de vida: `packed`, `in_transit`, `received`, `return_open`, `conflict`, `audited`. |
| `packages/{packageId}/events/{eventId}` | `TraceEvent` | Cada evento con su CVV cifrado (`cvvCiphertext`, `cvvIv`, `cvvAuthTag`), sello CSG y estado `valid`, `invalidated_csg` o `conflict`. |
| `auditLogs/{logId}` | `AuditLog` | Sólo creación. Nunca se modifica ni se borra desde el cliente. |
| `pilotConfigs/{userId}` | `PilotConfig` | Configuración privada del piloto por usuario. |

Tipos de evento: `pack`, `dispatch`, `receive`, `return`, `material_validation`, `csg_invalidation`, `conflict_detected`.

### Criptografía

| Capa | Mecanismo | Uso |
|---|---|---|
| Sellado de CVV | AES-256-GCM con AAD `packageId:eventId` | Cifra el payload del evento. La clave vive en IndexedDB del navegador como clave no exportable. |
| Sello CSG | HMAC-SHA256 sobre `packageId\|eventId\|eventType\|nonce\|authTag` | Detecta cambios de secuencia o de paquete. |
| Aceptación de recepción | ECDSA P-256 (`TAI-ACCEPT-V2`) | El receptor firma la QR de aceptación; la firma se valida al escanear. |
| Sello de estación | ECDSA P-256, certificado de estación (`TAI-STATION-CERT-V1`) y prueba de evento (`TAI-EVENT-PROOF-V1`) | Autentica los lotes offline importados. |
| Bóveda offline | PBKDF2-SHA256 (310 000 iteraciones) + AES-256-GCM, TTL de 7 días | Protege la estación HTML exportada y la cola cifrada. |

El proveedor CSG activo es `webcrypto-ecdsa-p256-hmac-v1`. El adaptador para el crate Rust `sello_integridad` está previsto pero **no está enlazado**, y la aplicación lo declara así en la interfaz.

## Estructura del repositorio

```
server.ts                      Servidor Express + endpoints /api/*
index.html, vite.config.ts     Entrada y configuración de Vite
src/
  App.tsx                      Shell, autenticación, cola offline, navegación
  main.tsx
  components/                  Secciones de la interfaz (Resumen, Embalaje, Transferencias,
                               Auditoría CSG, Centro Logístico) y modales/QR
  lib/
    firebase.ts                Inicialización de Firebase y Firestore offline
    taiService.ts              Operaciones de dominio (paquetes, eventos, auditoría, configuración)
    localCrypto.ts             Sellado y verificación CVV en el dispositivo
    offlineCrypto.ts           Bóveda, firmas ECDSA, cola cifrada, pruebas de estación
    offlineSyncEngine.ts       Validación de lotes importados y sincronización idempotente
    offlineHtmlExporter.ts     Generación de la estación offline en HTML protegido
    sheets.ts, googlePicker.ts Google Sheets y selector de Drive
  types/tai.ts                 Tipos y límites de longitud (BLUEPRINT_LIMITS)
tests/taiOfflineWorkflow.test.ts  Pruebas del flujo offline y criptográfico
firestore.rules                Reglas de seguridad de Firestore (vigentes)
DRAFT_firestore.rules          Borrador de las reglas (difiere sólo en comentarios)
firestore.rules.test.ts        Definición de los casos "Dirty Dozen" (sin runner)
security_spec.md               Invariantes de datos y casos adversarios
firebase-blueprint.json        Blueprint de datos de Firebase
.github/workflows/ci.yml       CI: typecheck, pruebas y build
```

## Requisitos

- Node.js 22 o superior (la CI usa Node 22).
- Bun, para instalar dependencias desde `bun.lock`.
- Un proyecto de Firebase con Authentication (proveedor Google) y Cloud Firestore habilitados.
- Una API key de Gemini para la pestaña Centro Logístico.

## Puesta en marcha

```bash
# 1. Dependencias (el lockfile vigente es bun.lock)
bun install

# 2. Variables de entorno
cp .env.example .env
# Completar GEMINI_API_KEY y, recomendado, TAI_SEALING_SECRET (ver abajo)

# 3. Desarrollo (Express + Vite en http://localhost:3000)
npm run dev

# 4. Producción
npm run build
NODE_ENV=production npm start
```

### Variables de entorno

| Variable | Obligatoria | Descripción |
|---|---|---|
| `GEMINI_API_KEY` | Sí, para Centro Logístico | Clave de Gemini. Sin ella, `/api/maps-grounding` responde 503. |
| `APP_URL` | No | URL pública de la aplicación. Sólo se documenta; no la lee el código actual. |
| `TAI_SEALING_SECRET` | Recomendada | Semilla (mínimo 16 caracteres) para la clave AES/HMAC del servidor. Si falta, el servidor genera una clave efímera y los sellos emitidos por el servidor dejan de verificarse al reiniciar. **No aparece en `.env.example`.** |

`dotenv` carga el archivo `.env` en la raíz.

### Firebase

La configuración pública del cliente está en `firebase-applet-config.json`, apuntando al proyecto `useful-cyclist-502606-u7`. Para usar otro proyecto:

1. Reemplazar `firebase-applet-config.json` con la configuración del nuevo proyecto (incluido `firestoreDatabaseId`).
2. Desplegar las reglas: `firestore.rules`.
3. Ajustar el correo administrador en la función `isAdmin()` de las reglas, que hoy está fijo en el código.
4. Restringir la API key en la consola de Google Cloud (referrers HTTP permitidos).

## Scripts

| Comando | Qué hace |
|---|---|
| `npm run dev` / `npm start` | Levanta Express con Vite (`tsx server.ts`), puerto 3000. |
| `npm run build` | Build de producción con Vite en `dist/`. |
| `npm run preview` | Sirve el build de Vite. |
| `npm run lint` | Typecheck con `tsc --noEmit`. |
| `npm test` | Pruebas `node:test` del flujo offline y criptográfico (5 casos). |
| `npm run lint:rules` | ESLint con el plugin de seguridad de Firebase sobre las reglas. |
| `npm run clean` | Borra `dist` y `server.js`. |

## Seguridad

Las invariantes y los casos adversarios están documentados en `security_spec.md`:

- Ningún operador puede crear o modificar registros en nombre de otro `ownerId`, ni sin correo verificado.
- Un evento sólo puede crearse si su paquete padre existe y pertenece al usuario.
- `auditLogs` es de sólo creación.
- Un CVV invalidado por CSG no puede volver a `valid` desde un cliente estándar.
- `pilotConfigs` es privado para cada UID.
- Los timestamps se validan contra `request.time` y se limita el tamaño de cada campo.

Los 12 casos "Dirty Dozen" (P01–P12) están definidos en `firestore.rules.test.ts`. **Hoy son sólo datos:** no existe un runner que los ejecute contra el emulador de Firestore. La verificación automatizada de reglas se limita al lint del plugin de seguridad (`npm run lint:rules`).

## Pruebas y CI

`npm test` ejecuta cinco casos que cubren:

1. Firma y validación de la QR de aceptación (ECDSA P-256), con rechazo de QR alteradas o sin firma.
2. Generación de la estación offline HTML, desbloqueo de la bóveda, sellado offline y verificación entre estaciones.
3. Cola offline cifrada y snapshot de paquetes que sobreviven a un reinicio sin conexión.
4. Sincronización parcial: sólo se confirman los eventos recibidos y el reintento es idempotente.
5. Transparencia del proveedor CSG y escape de etiquetas de cierre `</script>` en el runtime HTML.

El workflow `.github/workflows/ci.yml` corre en push y pull request a `main`/`master`: `typecheck`, `test` y `build`.

## Limitaciones conocidas

Hallazgos del análisis del código. Conviene resolverlos antes de un despliegue fuera del piloto.

- **El job de CI falla en la instalación.** El workflow ejecuta `npm ci`, pero el repositorio no tiene `package-lock.json`; el lockfile es `bun.lock`. Solución: cambiar el paso a `bun install --frozen-lockfile` o generar y commitear un `package-lock.json`.
- **Endpoints sin autenticación.** `/api/crypto/seal`, `/api/crypto/verify` y `/api/maps-grounding` no validan identidad ni tienen límite de uso. `maps-grounding` consume cuota de Gemini, así que cualquiera que alcance el servidor puede generar costo.
- **`/api/crypto/seal` no lo usa el cliente.** El sellado en producción es local (`localCrypto.ts`). El endpoint del servidor sólo sirve si se usa directamente.
- **Verificación de respaldo sin clave persistente.** `/api/crypto/verify` depende de `TAI_SEALING_SECRET`. Sin esa variable, el servidor usa una clave efímera.
- **Claves del dispositivo.** Las claves AES y HMAC de sellado se generan no exportables en IndexedDB. Si se borra el almacenamiento del navegador, los CVV sellados en ese dispositivo no pueden volver a verificarse localmente.
- **Reglas duplicadas.** `firestore.rules` y `DRAFT_firestore.rules` difieren sólo en comentarios. Conviene dejar uno solo.
- **Casos "Dirty Dozen" sin ejecutar.** Ver la sección de seguridad.
- **Modelo de IA.** El endpoint usa `gemini-4-hydrogen`. Confirmar que el modelo esté disponible para la cuenta usada antes de un despliegue.
- **Bundle grande.** El build genera un chunk de unos 2,3 MB (≈670 kB gzip). Vite advierte sobre el tamaño; conviene dividir el código por rutas o componentes pesados.
- **Puerto fijo.** El servidor escucha en el puerto 3000 y en `0.0.0.0`, sin configuración por variable de entorno.
- **Metadatos heredados.** `package.json` conserva `"name": "react-example"` y versión `0.0.0`. Los comentarios de `.env.example` y `vite.config.ts` hacen referencia a AI Studio.
- **Sin i18n.** Toda la interfaz y los mensajes de error están en español.

## Documentación relacionada

- `security_spec.md` — invariantes de seguridad y casos adversarios.
- `metadata.json` — descripción y capacidades declaradas del proyecto.

## Licencia

No especificada. Agregar un archivo `LICENSE` antes de compartir el código fuera del equipo.
