import { getDeviceSigningIdentity } from './localCrypto';
import {
  buildOfflineCryptoBrowserRuntime,
  sealOfflineCredentialVault,
  sealTransferEventOffline,
  verifyTransferEventOffline,
} from './offlineCrypto';
import { OFFLINE_JSQR_JS, OFFLINE_QRCODE_JS } from './offlineVendorStrings';
import type {
  OfflinePendingEvent,
  PilotConfig,
  StationCertificate,
  TaiPackage,
  TraceEvent,
} from '../types/tai';

export { sealTransferEventOffline, verifyTransferEventOffline };

export interface OfflineHtmlExportParams {
  passphrase: string;
  user: {
    uid: string;
    email: string;
    displayName: string;
  };
  deviceId: string;
  packages: TaiPackage[];
  events: TraceEvent[];
  offlineQueue: OfflinePendingEvent[];
  pilotConfig: PilotConfig | null;
  issuerSigner?: { privateKey: CryptoKey; publicKeyB64u: string; keyId: string };
}

function safeJsonForHtmlScript(value: unknown): string {
  return JSON.stringify(value)
    .replace(/</g, '\\u003c')
    .replace(/>/g, '\\u003e')
    .replace(/&/g, '\\u0026')
    .replace(/\u2028/g, '\\u2028')
    .replace(/\u2029/g, '\\u2029');
}

export async function generateProtectedOfflineHtml(
  params: OfflineHtmlExportParams
): Promise<{
  html: string;
  filename: string;
  expiresAt: string;
  stationIdentity: { keyId: string; publicKeyB64u: string; stationCert?: StationCertificate };
}> {
  const issuerSigner = params.issuerSigner || (await getDeviceSigningIdentity());
  const { vaultEnvelope, stationIdentity, expiresAt } = await sealOfflineCredentialVault({
    passphrase: params.passphrase,
    operator: {
      uid: params.user.uid,
      email: params.user.email,
      displayName: params.user.displayName || params.user.email.split('@')[0] || 'Operador TAI',
      role: 'Operador Autorizado Offline',
    },
    deviceId: params.deviceId,
    issuerSigner,
  });

  const knownNonces = Array.from(
    new Set([
      ...params.events.filter((e) => e.cvvState === 'valid').map((e) => e.acceptanceNonce),
      ...params.offlineQueue.map((q) => q.acceptanceNonce),
    ])
  ).slice(0, 500);

  const bundlePayload = {
    vault: vaultEnvelope,
    pilotMeta: {
      solverOrg: params.pilotConfig?.solverOrg || 'Organización Postulante TAI',
      pilotFacility: params.pilotConfig?.pilotFacility || 'Centro Logístico Buenos Aires — YPF',
      trlLevel: params.pilotConfig?.trlLevel || 'TRL 4–5',
    },
    packages: params.packages.map((p) => ({
      id: p.id,
      code: p.code,
      fromArea: p.fromArea,
      targetArea: p.targetArea,
      zone: p.zone,
      contentSummary: p.contentSummary,
      quantity: p.quantity,
      unit: p.unit,
      sealStatus: p.sealStatus,
      lifecycleStatus: p.lifecycleStatus,
    })),
    knownNonces,
  };

  const dateSlug = new Date().toISOString().slice(0, 10);
  const filename = `tai-estacion-offline-${dateSlug}.html`;
  const html = buildStandaloneHtmlDocument(bundlePayload);

  return { html, filename, expiresAt, stationIdentity };
}

function buildStandaloneHtmlDocument(bundlePayload: unknown): string {
  const safeJson = safeJsonForHtmlScript(bundlePayload);

  return `<!doctype html>
<html lang="es">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>TAI — Estación Autónoma Offline | Piloto YPF</title>
  <style>
    :root {
      --bg: #f8fafc;
      --surface: #ffffff;
      --surface-muted: #f1f5f9;
      --border: #e2e8f0;
      --text: #0f172a;
      --muted: #64748b;
      --accent: #0369a1;
      --accent-hover: #075985;
      --ok: #047857;
      --ok-bg: #ecfdf5;
      --ok-border: #a7f3d0;
      --warn: #92400e;
      --warn-bg: #fffbeb;
      --warn-border: #fde68a;
      --danger: #991b1b;
      --danger-bg: #fef2f2;
      --danger-border: #fecaca;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Inter, Helvetica, Arial, sans-serif;
      background: var(--bg);
      color: var(--text);
      line-height: 1.5;
      -webkit-font-smoothing: antialiased;
    }
    .mono { font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace; }
    .hidden { display: none !important; }
    .container { max-width: 1200px; margin: 0 auto; padding: 0 20px; }
    header {
      background: var(--surface);
      border-bottom: 1px solid var(--border);
      position: sticky;
      top: 0;
      z-index: 30;
    }
    .header-inner {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 16px;
      padding: 12px 20px;
      max-width: 1200px;
      margin: 0 auto;
    }
    .brand { display: flex; align-items: center; gap: 10px; }
    .brand-badge {
      width: 34px; height: 34px;
      border-radius: 8px;
      background: var(--text);
      color: #fff;
      font-weight: 800;
      font-size: 13px;
      display: inline-flex;
      align-items: center;
      justify-content: center;
      letter-spacing: 0.04em;
    }
    .brand-title { font-size: 14px; font-weight: 700; margin: 0; }
    .brand-sub { font-size: 11px; color: var(--muted); margin: 0; }
    .nav-tabs { display: flex; gap: 18px; align-items: center; }
    .nav-tab {
      background: none; border: none; border-bottom: 2px solid transparent;
      padding: 4px 2px; font-size: 13px; font-weight: 500; color: var(--muted); cursor: pointer;
    }
    .nav-tab.active { color: var(--text); font-weight: 700; border-bottom-color: var(--accent); }
    .toolbar {
      background: #f1f5f9;
      border-bottom: 1px solid var(--border);
      padding: 8px 0;
      font-size: 12px;
      color: var(--muted);
    }
    .toolbar-inner {
      display: flex; flex-wrap: wrap; align-items: center; justify-content: space-between; gap: 10px;
    }
    .status-chip {
      display: inline-flex; align-items: center; gap: 6px;
      padding: 4px 10px; border-radius: 8px;
      font-size: 12px; font-weight: 600;
      border: 1px solid var(--warn-border); background: var(--warn-bg); color: var(--warn);
    }
    .status-chip.ok {
      border-color: var(--ok-border); background: var(--ok-bg); color: var(--ok);
    }
    main { padding: 24px 20px 48px; max-width: 1200px; margin: 0 auto; }
    .card {
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: 12px;
      padding: 20px;
      margin-bottom: 20px;
    }
    .card-header {
      display: flex; flex-wrap: wrap; align-items: center; justify-content: space-between; gap: 12px;
      padding-bottom: 14px; margin-bottom: 16px; border-bottom: 1px solid #f1f5f9;
    }
    .card-title { font-size: 15px; font-weight: 700; margin: 0; }
    .card-sub { font-size: 12px; color: var(--muted); margin: 3px 0 0; }
    .grid { display: grid; gap: 20px; grid-template-columns: 1fr; }
    @media (min-width: 960px) {
      .grid-12 { grid-template-columns: 7fr 5fr; }
      .grid-2 { grid-template-columns: 1fr 1fr; }
      .grid-qr { grid-template-columns: 200px 1fr; }
    }
    label { display: block; font-size: 12px; font-weight: 600; color: #334155; margin-bottom: 4px; }
    input, select, textarea {
      width: 100%; padding: 8px 10px; font-size: 12px; border-radius: 8px;
      border: 1px solid #cbd5e1; background: #fff; color: var(--text); font-family: inherit;
    }
    input:focus, select:focus, textarea:focus {
      outline: none; border-color: var(--accent);
    }
    .btn {
      display: inline-flex; align-items: center; justify-content: center; gap: 6px;
      padding: 8px 14px; font-size: 12px; font-weight: 600; border-radius: 8px;
      border: 1px solid #cbd5e1; background: #fff; color: var(--text); cursor: pointer;
    }
    .btn:hover:not(:disabled) { background: #f8fafc; }
    .btn:disabled { opacity: 0.45; cursor: not-allowed; }
    .btn-primary { background: var(--accent); border-color: var(--accent); color: #fff; }
    .btn-primary:hover:not(:disabled) { background: var(--accent-hover); }
    .btn-dark { background: #0f172a; border-color: #0f172a; color: #fff; }
    .btn-dark:hover:not(:disabled) { background: #1e293b; }
    .btn-danger { background: var(--danger-bg); border-color: var(--danger-border); color: var(--danger); }
    .btn-warn { background: var(--warn-bg); border-color: var(--warn-border); color: var(--warn); }
    .seg-group {
      display: inline-flex; gap: 4px; background: var(--surface-muted); padding: 4px; border-radius: 8px;
    }
    .seg-btn {
      border: none; background: transparent; padding: 5px 10px; font-size: 12px; font-weight: 600;
      color: var(--muted); border-radius: 6px; cursor: pointer;
    }
    .seg-btn.active { background: #fff; color: var(--text); box-shadow: 0 1px 2px rgba(0,0,0,0.06); }
    .alert {
      border-radius: 8px; padding: 10px 12px; font-size: 12px; font-weight: 500;
      border: 1px solid var(--border); background: #f8fafc; margin-top: 12px;
    }
    .alert.ok { border-color: var(--ok-border); background: var(--ok-bg); color: var(--ok); }
    .alert.warn { border-color: var(--warn-border); background: var(--warn-bg); color: var(--warn); }
    .alert.danger { border-color: var(--danger-border); background: var(--danger-bg); color: var(--danger); }
    .qr-box {
      border: 1px solid var(--border); border-radius: 10px; padding: 12px;
      background: #fff; text-align: center;
    }
    .qr-box img { display: block; margin: 0 auto; width: 164px; height: 164px; }
    .camera-box {
      position: relative; margin-top: 12px; border-radius: 10px; overflow: hidden;
      background: #020617; border: 1px solid var(--border);
    }
    .camera-box video { width: 100%; max-height: 260px; object-fit: cover; display: block; }
    .camera-reticle {
      position: absolute; inset: 0; display: flex; align-items: center; justify-content: center; pointer-events: none;
    }
    .camera-reticle div {
      width: 170px; height: 170px; border: 2px solid #38bdf8; border-radius: 10px;
      box-shadow: 0 0 0 9999px rgba(2,6,23,0.35);
    }
    .list-item {
      border: 1px solid var(--border); border-radius: 8px; padding: 10px 12px;
      font-size: 12px; background: #fff; margin-top: 8px;
    }
    .list-item.pending { border-color: var(--warn-border); background: #fffbeb80; }
    .row { display: flex; flex-wrap: wrap; gap: 10px; align-items: center; }
    .space-y > * + * { margin-top: 12px; }
    .truncate { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
    table { width: 100%; border-collapse: collapse; font-size: 12px; }
    th, td { text-align: left; padding: 8px 10px; border-bottom: 1px solid var(--border); }
    th { background: var(--surface-muted); font-weight: 700; font-size: 11px; color: #475569; }
    .auth-wrapper { max-width: 520px; margin: 40px auto; }
  </style>
</head>
<body>
  <header>
    <div class="header-inner">
      <div class="brand">
        <div class="brand-badge">TAI</div>
        <div>
          <p class="brand-title">TAI — Estación Autónoma Sin Internet</p>
          <p class="brand-sub" id="hdr-facility">Centro Logístico Buenos Aires</p>
        </div>
      </div>

      <nav class="nav-tabs hidden" id="nav-tabs">
        <button type="button" class="nav-tab active" data-tab="transfers">Transferencias y CVV</button>
        <button type="button" class="nav-tab" data-tab="audit">Validación CSG</button>
        <button type="button" class="nav-tab" data-tab="vault">Paquetes y Credencial</button>
      </nav>

      <div class="row">
        <span class="status-chip" id="hdr-auth-badge">Credencial bloqueada</span>
        <button type="button" class="btn hidden" id="btn-lock-session">Bloquear sesión</button>
      </div>
    </div>
  </header>

  <div class="toolbar">
    <div class="container toolbar-inner">
      <span>Operación autónoma offline · Web Crypto AES-256-GCM + CSG HMAC-SHA256</span>
      <span id="hdr-net-state" class="mono">Modo autónomo local (sin dependencias externas)</span>
    </div>
  </div>

  <main>
    <!-- Auth / Unlock Screen -->
    <section id="auth-gate" class="auth-wrapper">
      <div class="card">
        <div class="card-header">
          <div>
            <h1 class="card-title">Autenticación y Desbloqueo de Credencial Offline</h1>
            <p class="card-sub">
              Ingresa la clave definida al descargar esta estación para validar tu identidad, habilitar el escáner y sellar eventos CVV sin internet.
            </p>
          </div>
        </div>

        <form id="unlock-form" class="space-y">
          <div class="alert">
            <div><strong>Bóveda:</strong> <span class="mono" id="vault-alg-label"></span></div>
            <div style="margin-top:4px;"><strong>Vigencia hasta:</strong> <span class="mono" id="vault-exp-label"></span></div>
          </div>

          <div>
            <label for="unlock-passphrase">Clave / PIN de operador offline</label>
            <input id="unlock-passphrase" type="password" autocomplete="current-password" required placeholder="Ingresa tu clave offline..." />
          </div>

          <div id="unlock-error" class="alert danger hidden"></div>

          <button type="submit" class="btn btn-primary" style="width:100%;" id="btn-unlock">
            Autenticar y desbloquear estación TAI
          </button>
        </form>
      </div>
    </section>

    <!-- Main App Workspace (Unlocked) -->
    <section id="workspace" class="hidden">
      <!-- Tab 1: Transfers & Offline CVV -->
      <div id="tab-transfers">
        <div class="card">
          <div class="row" style="justify-content: space-between;">
            <div class="row" style="flex:1; min-width:260px;">
              <label for="pkg-select" style="margin:0; white-space:nowrap;">Unidad logística activa:</label>
              <select id="pkg-select" style="max-width:460px;"></select>
            </div>
            <div class="status-chip ok" id="operator-chip"></div>
          </div>
        </div>

        <div class="grid grid-12">
          <!-- Left: Step 1 & Step 2 -->
          <div>
            <!-- Step 1: Receiver -->
            <div class="card">
              <div class="card-header">
                <div>
                  <h2 class="card-title">1. Dispositivo del receptor · QR de aceptación</h2>
                  <p class="card-sub">Genera el QR de aceptación ligado al paquete y evento sin conexión.</p>
                </div>
                <div class="seg-group" id="event-mode-group">
                  <button type="button" class="seg-btn" data-mode="dispatch">Despacho</button>
                  <button type="button" class="seg-btn active" data-mode="receive">Recepción</button>
                  <button type="button" class="seg-btn" data-mode="return">Devolución</button>
                </div>
              </div>

              <div class="grid grid-qr">
                <div class="space-y">
                  <div class="qr-box">
                    <img id="acceptance-qr-img" alt="QR de aceptación TAI" />
                    <div class="mono" id="acceptance-nonce-label" style="font-size:11px; margin-top:6px; color:#475569;"></div>
                  </div>
                  <button type="button" class="btn" id="btn-new-acceptance" style="width:100%;">
                    Generar nuevo QR de entrega
                  </button>
                </div>

                <div class="space-y">
                  <div>
                    <label for="receiver-name">Receptor (quien genera el QR)</label>
                    <input id="receiver-name" type="text" value="Módulo Mantenimiento Compresores" maxlength="120" />
                  </div>
                  <div>
                    <label for="zone-name">Zona / Área de recepción</label>
                    <input id="zone-name" type="text" value="Zona Operativa Sur · Dock Sud" maxlength="120" />
                  </div>
                  <div class="alert">
                    <strong>Cadena QR activa:</strong>
                    <div id="acceptance-qr-text" class="mono truncate" style="margin-top:4px; font-size:11px;"></div>
                  </div>
                </div>
              </div>
            </div>

            <!-- Step 2: Deliverer Camera + Validation + CVV Generation -->
            <div class="card">
              <div class="card-header">
                <div>
                  <h2 class="card-title">2. Dispositivo de quien entrega · Escáner y generación CVV</h2>
                  <p class="card-sub">Captura el QR del receptor con cámara o imagen, valídalo como inicio y sella el CVV offline.</p>
                </div>
                <div class="row">
                  <button type="button" class="btn btn-dark" id="btn-toggle-camera">Escanear con cámara</button>
                  <label class="btn" style="margin:0;">
                    Imagen QR
                    <input id="qr-file-input" type="file" accept="image/*" class="hidden" />
                  </label>
                  <button type="button" class="btn" id="btn-read-shown-qr">Leer QR mostrado</button>
                </div>
              </div>

              <div id="camera-container" class="camera-box hidden">
                <video id="camera-video" playsinline muted autoplay></video>
                <div class="camera-reticle"><div></div></div>
              </div>
              <div id="camera-error" class="alert warn hidden"></div>

              <div class="row" style="margin-top:12px;">
                <input id="manual-qr-input" type="text" class="mono" placeholder="Pegar cadena QR escaneada (tai://accept|...)" style="flex:1;" />
                <button type="button" class="btn" id="btn-load-manual-qr">Validar QR</button>
              </div>

              <div id="validated-qr-banner" class="alert" style="margin-top:14px;">
                Captura y valida el QR de aceptación del receptor antes de generar el CVV.
              </div>

              <form id="cvv-form" class="space-y" style="margin-top:14px;">
                <div class="grid grid-2">
                  <div>
                    <label for="deliverer-name">Quien entrega</label>
                    <input id="deliverer-name" type="text" value="Transporte Interno BA-04" required maxlength="120" />
                  </div>
                  <div>
                    <label for="function-role">Función / Rol</label>
                    <input id="function-role" type="text" value="Operador que Entrega" required maxlength="120" />
                  </div>
                </div>

                <div>
                  <label for="seal-status">Inspección física del cierre TAI</label>
                  <select id="seal-status">
                    <option value="intact">Cierre intacto y etiqueta legible</option>
                    <option value="opened">Abierto por inspección autorizada</option>
                    <option value="damaged">Dañado / incidencia reportada</option>
                  </select>
                </div>

                <div id="discrepancy-group" class="hidden">
                  <label for="discrepancy-note">Cantidad observada y discrepancia de devolución</label>
                  <input id="discrepancy-note" type="text" maxlength="400" placeholder="Ej. Se devuelven 2 piezas sin uso; 1 empaque abierto." />
                </div>

                <div>
                  <label for="observations">Observaciones</label>
                  <textarea id="observations" rows="2" maxlength="500">Cierre TAI intacto. Captura realizada en estación offline.</textarea>
                </div>

                <div id="cvv-feedback" class="alert hidden"></div>

                <button type="submit" class="btn btn-primary" id="btn-generate-cvv" disabled style="width:100%; padding:10px 14px;">
                  Generar CVV offline y guardar en cola local
                </button>
              </form>
            </div>
          </div>

          <!-- Right: Offline Queue & Export -->
          <div>
            <div class="card">
              <div class="card-header">
                <div>
                  <h3 class="card-title">3. Cola offline del dispositivo (<span id="queue-count">0</span>)</h3>
                  <p class="card-sub">Eventos ya sellados con credencial protegida; expórtalos para importar al recuperar red.</p>
                </div>
                <button type="button" class="btn btn-dark" id="btn-export-batch" disabled>
                  Exportar lote (.json)
                </button>
              </div>
              <div id="offline-queue-list">
                <p style="font-size:12px; color:var(--muted);">Aún no hay eventos CVV generados en esta sesión offline.</p>
              </div>
            </div>
          </div>
        </div>
      </div>

      <!-- Tab 2: CSG Verification Offline -->
      <div id="tab-audit" class="hidden">
        <div class="card">
          <div class="card-header">
            <div>
              <h2 class="card-title">Verificación AES-256-GCM y sellado CSG sin internet</h2>
              <p class="card-sub">Valida localmente la autenticidad e integridad de cualquier CVV generado en la estación offline.</p>
            </div>
          </div>

          <div class="space-y">
            <div>
              <label for="audit-event-select">Evento CVV en cola local</label>
              <select id="audit-event-select" class="mono"></select>
            </div>

            <div id="audit-crypto-preview" class="alert mono hidden" style="font-size:11px;"></div>

            <div class="row">
              <button type="button" class="btn btn-primary" id="btn-verify-cvv" disabled>Verificar integridad CVV</button>
              <button type="button" class="btn btn-danger" id="btn-tamper-cvv" disabled>Simular alteración CSG</button>
            </div>

            <div id="audit-result" class="alert hidden"></div>
          </div>
        </div>
      </div>

      <!-- Tab 3: Packages & Credential Info -->
      <div id="tab-vault" class="hidden">
        <div class="card">
          <div class="card-header">
            <div>
              <h2 class="card-title">Credencial protegida del operador</h2>
              <p class="card-sub">Desbloqueada exclusivamente en memoria mediante PBKDF2-SHA256 + AES-256-GCM.</p>
            </div>
          </div>
          <div id="credential-details" class="space-y" style="font-size:12px;"></div>
        </div>

        <div class="card">
          <div class="card-header">
            <div>
              <h2 class="card-title">Catálogo de paquetes sincronizado (<span id="pkg-count">0</span>)</h2>
              <p class="card-sub">Instantánea operativa disponible para validación sin conexión.</p>
            </div>
          </div>
          <div style="overflow-x:auto;">
            <table>
              <thead>
                <tr>
                  <th>Código</th>
                  <th>FROM</th>
                  <th>Destino</th>
                  <th>Contenido</th>
                  <th>Estado</th>
                </tr>
              </thead>
              <tbody id="packages-table-body"></tbody>
            </table>
          </div>
        </div>
      </div>
    </section>
  </main>

  <script id="tai-offline-bundle" type="application/json">${safeJson}</script>
  <script>${OFFLINE_QRCODE_JS}</script>
  <script>${OFFLINE_JSQR_JS}</script>
  <script>${buildOfflineCryptoBrowserRuntime()}</script>
  <script>
  (function () {
    "use strict";
    var CryptoEngine = window.TaiOfflineCrypto;
    var bundleEl = document.getElementById("tai-offline-bundle");
    var BUNDLE = JSON.parse(bundleEl.textContent || "{}");

    // Unlocked runtime state (strictly in memory; wiped on lock)
    var session = null; // { operator, deviceId, issuedAt, expiresAt, aesKey, hmacKey, storageKey }
    var offlineQueue = [];
    var activeMode = "receive";
    var acceptanceNonce = "";
    var validatedQr = null;
    var cameraStream = null;
    var cameraRaf = null;
    var scanBusy = false;

    function $(id) { return document.getElementById(id); }

    function generateNonce() {
      return CryptoEngine.generateNonce();
    }

    function eventLabel(t) {
      if (t === "dispatch") return "Despacho";
      if (t === "return") return "Devolución";
      return "Recepción";
    }

    // Initialize static vault labels
    $("hdr-facility").textContent = (BUNDLE.pilotMeta && BUNDLE.pilotMeta.pilotFacility) || "Centro Logístico Buenos Aires";
    $("vault-alg-label").textContent = (BUNDLE.vault && BUNDLE.vault.algorithm) || "PBKDF2 + AES-256-GCM";
    $("vault-exp-label").textContent = (BUNDLE.vault && BUNDLE.vault.expiresAt) || "";

    async function unlockVault(passphrase) {
      session = await CryptoEngine.unlockVault(BUNDLE.vault, passphrase);
      await loadEncryptedQueue();
    }

    async function saveEncryptedQueue() {
      if (!session) return;
      try {
        var blob = await CryptoEngine.encryptQueueBlob(offlineQueue, session);
        localStorage.setItem(session.storageKey, JSON.stringify(blob));
      } catch (e) {
        // localStorage may be restricted in strict file:// private modes; in-memory queue still works
      }
    }

    async function loadEncryptedQueue() {
      offlineQueue = [];
      if (!session) return;
      try {
        var raw = localStorage.getItem(session.storageKey);
        if (!raw) return;
        var parsed = JSON.parse(raw);
        var items = await CryptoEngine.decryptQueueBlob(parsed, session);
        if (Array.isArray(items)) offlineQueue = items;
      } catch (e) {
        offlineQueue = [];
      }
    }

    function getSelectedPkg() {
      var id = $("pkg-select").value;
      var list = BUNDLE.packages || [];
      for (var i = 0; i < list.length; i++) {
        if (list[i].id === id) return list[i];
      }
      return list[0] || null;
    }

    var currentAcceptanceQr = "";

    async function renderAcceptanceQr() {
      var pkg = getSelectedPkg();
      if (!pkg || !session) {
        currentAcceptanceQr = "";
        $("acceptance-qr-text").textContent = "Sin paquetes disponibles";
        return;
      }
      var signed = await CryptoEngine.signAcceptanceQr({
        packageId: pkg.id,
        eventType: activeMode,
        nonce: acceptanceNonce,
        receiverName: $("receiver-name").value.trim() || session.operator.displayName || "Receptor en sitio",
        zone: $("zone-name").value.trim() || "Centro Logístico Buenos Aires"
      }, session);
      currentAcceptanceQr = signed.qrString;
      $("acceptance-qr-text").textContent = signed.qrString;
      $("acceptance-nonce-label").textContent = (signed.acceptanceCryptoId || acceptanceNonce) + " · Firma #" + session.stationKeyId;
      if (signed.qrString && window.TaiQrLib && typeof window.TaiQrLib.toDataURL === "function") {
        window.TaiQrLib.toDataURL(signed.qrString, { width: 180, margin: 1, errorCorrectionLevel: "M" }, function (err, url) {
          if (!err && url) $("acceptance-qr-img").src = url;
        });
      }
    }

    async function validateAcceptanceQr(raw) {
      var verified = await CryptoEngine.parseAndVerifyAcceptanceQr(raw);
      if (!verified.valid || !verified.parsed) {
        setFeedback(verified.reason || "El código escaneado no es un QR de aceptación TAI válido.", "warn");
        return false;
      }
      var parsed = verified.parsed;
      var list = BUNDLE.packages || [];
      var found = null;
      for (var i = 0; i < list.length; i++) {
        if (list[i].id === parsed.packageId || list[i].code === parsed.packageId) {
          found = list[i];
          break;
        }
      }
      if (!found) {
        setFeedback("El paquete (" + parsed.packageId + ") no figura en el catálogo sincronizado.", "warn");
        return false;
      }

      var known = BUNDLE.knownNonces || [];
      var dupKnown = known.indexOf(parsed.nonce) !== -1;
      var dupQueue = offlineQueue.some(function (q) { return q.acceptanceNonce === parsed.nonce; });
      if (dupKnown || dupQueue) {
        setFeedback("Este QR de aceptación (" + parsed.nonce + ") ya fue utilizado previamente.", "warn");
        return false;
      }

      validatedQr = {
        packageId: found.id,
        packageCode: found.code,
        eventType: parsed.eventType,
        nonce: parsed.nonce,
        acceptanceHash: parsed.acceptanceHash,
        acceptanceCryptoId: parsed.acceptanceCryptoId,
        receiverName: parsed.receiverName,
        zone: parsed.zone,
        receiverUid: parsed.receiverUid,
        receiverDeviceId: parsed.receiverDeviceId,
        proof: parsed.proof
      };

      $("pkg-select").value = found.id;
      activeMode = parsed.eventType;
      updateModeButtons();
      $("receiver-name").value = parsed.receiverName;
      $("zone-name").value = parsed.zone;

      var banner = $("validated-qr-banner");
      banner.className = "alert ok";
      banner.textContent = "Receptor verificado (" + parsed.receiverUid + " · #" + parsed.proof.receiverKeyId + ") · ID " + parsed.acceptanceCryptoId + " · " + eventLabel(parsed.eventType) + " · Paquete " + found.code;
      $("btn-generate-cvv").disabled = false;
      setFeedback("QR de aceptación firmado y verificado. Ya puedes generar el CVV offline.", "ok");
      return true;
    }

    function setFeedback(msg, kind) {
      var el = $("cvv-feedback");
      if (!msg) { el.classList.add("hidden"); return; }
      el.className = "alert " + (kind === "ok" ? "ok" : kind === "danger" ? "danger" : "warn");
      el.textContent = msg;
    }

    function updateModeButtons() {
      var btns = document.querySelectorAll("#event-mode-group .seg-btn");
      btns.forEach(function (b) {
        b.classList.toggle("active", b.getAttribute("data-mode") === activeMode);
      });
      $("discrepancy-group").classList.toggle("hidden", activeMode !== "return");
      $("discrepancy-note").required = activeMode === "return";
      void renderAcceptanceQr();
    }

    function stopCamera() {
      if (cameraRaf) cancelAnimationFrame(cameraRaf);
      cameraRaf = null;
      if (cameraStream) {
        cameraStream.getTracks().forEach(function (t) { t.stop(); });
        cameraStream = null;
      }
      $("camera-video").srcObject = null;
      $("camera-container").classList.add("hidden");
      $("btn-toggle-camera").textContent = "Escanear con cámara";
      $("btn-toggle-camera").className = "btn btn-dark";
    }

    async function startCamera() {
      $("camera-error").classList.add("hidden");
      if (!navigator.mediaDevices || !navigator.mediaDevices.getUserMedia) {
        $("camera-error").textContent = "La cámara no está disponible en este navegador o contexto.";
        $("camera-error").classList.remove("hidden");
        return;
      }
      try {
        cameraStream = await navigator.mediaDevices.getUserMedia({
          audio: false,
          video: { facingMode: { ideal: "environment" } }
        });
        var video = $("camera-video");
        video.srcObject = cameraStream;
        $("camera-container").classList.remove("hidden");
        $("btn-toggle-camera").textContent = "Detener cámara";
        $("btn-toggle-camera").className = "btn btn-danger";

        var canvas = document.createElement("canvas");
        var ctx = canvas.getContext("2d");

        var tick = async function () {
          if (!cameraStream) return;
          if (!scanBusy && video.readyState === video.HAVE_ENOUGH_DATA && window.TaiJsQrLib) {
            scanBusy = true;
            try {
              canvas.width = video.videoWidth || 640;
              canvas.height = video.videoHeight || 480;
              ctx.drawImage(video, 0, 0, canvas.width, canvas.height);
              var imgData = ctx.getImageData(0, 0, canvas.width, canvas.height);
              var res = window.TaiJsQrLib(imgData.data, canvas.width, canvas.height, { inversionAttempts: "dontInvert" });
              if (res && res.data && await validateAcceptanceQr(res.data)) {
                stopCamera();
                scanBusy = false;
                return;
              }
            } finally {
              scanBusy = false;
            }
          }
          cameraRaf = requestAnimationFrame(function () { void tick(); });
        };
        cameraRaf = requestAnimationFrame(function () { void tick(); });
      } catch (err) {
        stopCamera();
        $("camera-error").textContent = "No se pudo abrir la cámara (" + (err && err.message ? err.message : "permiso denegado") + "). Usa Imagen QR o Leer QR mostrado.";
        $("camera-error").classList.remove("hidden");
      }
    }

    function renderQueueAndAudit() {
      $("queue-count").textContent = String(offlineQueue.length);
      $("btn-export-batch").disabled = offlineQueue.length === 0;

      var container = $("offline-queue-list");
      container.textContent = "";
      if (offlineQueue.length === 0) {
        var p = document.createElement("p");
        p.style.fontSize = "12px";
        p.style.color = "var(--muted)";
        p.textContent = "Aún no hay eventos CVV generados en esta sesión offline.";
        container.appendChild(p);
      } else {
        offlineQueue.forEach(function (item) {
          var div = document.createElement("div");
          div.className = "list-item pending";

          var top = document.createElement("div");
          top.className = "row mono";
          top.style.justifyContent = "space-between";
          top.style.fontSize = "11px";
          top.style.color = "var(--warn)";
          var s1 = document.createElement("span");
          s1.textContent = item.packageCode + " · Seq #" + item.offlineSequence;
          var s2 = document.createElement("span");
          s2.textContent = item.deviceId;
          top.appendChild(s1);
          top.appendChild(s2);

          var mid = document.createElement("div");
          mid.style.fontWeight = "600";
          mid.style.marginTop = "4px";
          mid.textContent = eventLabel(item.eventType) + ": " + item.delivererName + " → " + item.receiverName;

          var c = document.createElement("div");
          c.className = "mono truncate";
          c.style.fontSize = "11px";
          c.style.color = "#475569";
          c.style.marginTop = "2px";
          c.textContent = "CVV: " + item.eventId + " · CSG: " + item.csgSeal.slice(0, 18) + "…";

          div.appendChild(top);
          div.appendChild(mid);
          div.appendChild(c);
          container.appendChild(div);
        });
      }

      // Populate Audit Selector
      var sel = $("audit-event-select");
      sel.textContent = "";
      if (offlineQueue.length === 0) {
        var opt = document.createElement("option");
        opt.value = "";
        opt.textContent = "Genera primero un evento CVV offline";
        sel.appendChild(opt);
        $("btn-verify-cvv").disabled = true;
        $("btn-tamper-cvv").disabled = true;
        $("audit-crypto-preview").classList.add("hidden");
      } else {
        offlineQueue.forEach(function (item) {
          var opt = document.createElement("option");
          opt.value = item.eventId;
          opt.textContent = item.eventId + " · " + item.packageCode + " (" + eventLabel(item.eventType) + ")";
          sel.appendChild(opt);
        });
        $("btn-verify-cvv").disabled = false;
        $("btn-tamper-cvv").disabled = false;
        renderAuditPreview();
      }
    }

    function renderAuditPreview() {
      var id = $("audit-event-select").value;
      var item = offlineQueue.find(function (q) { return q.eventId === id; }) || offlineQueue[0];
      var preview = $("audit-crypto-preview");
      if (!item) { preview.classList.add("hidden"); return; }
      preview.classList.remove("hidden");
      preview.textContent = "Event ID: " + item.eventId + " | IV: " + item.cvvIv + " | AuthTag: " + item.cvvAuthTag + " | CSG: " + item.csgSeal.slice(0, 28) + "…";
    }

    async function verifySelectedCvv(tamper) {
      if (!session) return;
      var id = $("audit-event-select").value;
      var item = offlineQueue.find(function (q) { return q.eventId === id; });
      if (!item) return;

      var resBox = $("audit-result");
      var result = await CryptoEngine.verifyTransferEvent(item, session, tamper);
      resBox.className = result.valid ? "alert ok" : "alert danger";
      resBox.textContent = result.reason;
      resBox.classList.remove("hidden");
    }

    function populatePackagesAndCredentials() {
      var pkgs = BUNDLE.packages || [];
      var sel = $("pkg-select");
      sel.textContent = "";
      if (pkgs.length === 0) {
        var opt = document.createElement("option");
        opt.value = "";
        opt.textContent = "Sin paquetes sincronizados";
        sel.appendChild(opt);
      } else {
        pkgs.forEach(function (p) {
          var opt = document.createElement("option");
          opt.value = p.id;
          opt.textContent = p.code + " — " + p.fromArea + " → " + p.targetArea;
          sel.appendChild(opt);
        });
      }

      $("pkg-count").textContent = String(pkgs.length);
      var tbody = $("packages-table-body");
      tbody.textContent = "";
      pkgs.forEach(function (p) {
        var tr = document.createElement("tr");
        [p.code, p.fromArea, p.targetArea, p.contentSummary + " (" + p.quantity + " " + p.unit + ")", p.lifecycleStatus].forEach(function (val) {
          var td = document.createElement("td");
          td.textContent = String(val || "");
          tr.appendChild(td);
        });
        tbody.appendChild(tr);
      });

      if (session) {
        var det = $("credential-details");
        det.textContent = "";
        [
          "Operador autenticado: " + session.operator.displayName + " (" + session.operator.email + ")",
          "UID protegido: " + session.operator.uid,
          "Dispositivo autorizado: " + session.deviceId,
          "Clave de firma estación (ECDSA P-256): #" + session.stationKeyId + (session.stationCert ? " · Certificada por #" + session.stationCert.issuerKeyId : ""),
          "Emitida: " + session.issuedAt,
          "Expira: " + session.expiresAt,
          "Criptografía activa: Piloto Web Crypto (PBKDF2-SHA256 + AES-256-GCM + ECDSA P-256 + HMAC-SHA256; adaptador preparado para crate Rust sello_integridad)"
        ].forEach(function (line) {
          var div = document.createElement("div");
          div.className = "mono";
          div.textContent = line;
          det.appendChild(div);
        });
      }
    }

    // Event bindings
    $("unlock-form").addEventListener("submit", async function (e) {
      e.preventDefault();
      var errEl = $("unlock-error");
      errEl.classList.add("hidden");
      $("btn-unlock").disabled = true;
      $("btn-unlock").textContent = "Verificando credencial...";
      try {
        var pass = $("unlock-passphrase").value;
        await unlockVault(pass);
        $("unlock-passphrase").value = "";

        $("auth-gate").classList.add("hidden");
        $("workspace").classList.remove("hidden");
        $("nav-tabs").classList.remove("hidden");
        $("btn-lock-session").classList.remove("hidden");
        $("hdr-auth-badge").className = "status-chip ok";
        $("hdr-auth-badge").textContent = session.operator.email;
        $("operator-chip").textContent = "Operador: " + session.operator.email;

        acceptanceNonce = generateNonce();
        populatePackagesAndCredentials();
        await renderAcceptanceQr();
        renderQueueAndAudit();
      } catch (err) {
        errEl.textContent = (err && err.message) ? err.message : "Clave incorrecta o bóveda dañada.";
        errEl.classList.remove("hidden");
      } finally {
        $("btn-unlock").disabled = false;
        $("btn-unlock").textContent = "Autenticar y desbloquear estación TAI";
      }
    });

    $("btn-lock-session").addEventListener("click", function () {
      stopCamera();
      session = null;
      offlineQueue = [];
      validatedQr = null;
      $("workspace").classList.add("hidden");
      $("nav-tabs").classList.add("hidden");
      $("btn-lock-session").classList.add("hidden");
      $("auth-gate").classList.remove("hidden");
      $("hdr-auth-badge").className = "status-chip";
      $("hdr-auth-badge").textContent = "Credencial bloqueada";
    });

    document.querySelectorAll(".nav-tab").forEach(function (btn) {
      btn.addEventListener("click", function () {
        var tab = btn.getAttribute("data-tab");
        document.querySelectorAll(".nav-tab").forEach(function (b) {
          b.classList.toggle("active", b === btn);
        });
        $("tab-transfers").classList.toggle("hidden", tab !== "transfers");
        $("tab-audit").classList.toggle("hidden", tab !== "audit");
        $("tab-vault").classList.toggle("hidden", tab !== "vault");
      });
    });

    document.querySelectorAll("#event-mode-group .seg-btn").forEach(function (btn) {
      btn.addEventListener("click", function () {
        activeMode = btn.getAttribute("data-mode") || "receive";
        updateModeButtons();
      });
    });

    $("pkg-select").addEventListener("change", function () { void renderAcceptanceQr(); });
    $("receiver-name").addEventListener("input", function () { void renderAcceptanceQr(); });
    $("zone-name").addEventListener("input", function () { void renderAcceptanceQr(); });
    $("btn-new-acceptance").addEventListener("click", function () {
      acceptanceNonce = generateNonce();
      void renderAcceptanceQr();
    });

    $("btn-toggle-camera").addEventListener("click", function () {
      if (cameraStream) stopCamera();
      else void startCamera();
    });

    $("btn-read-shown-qr").addEventListener("click", async function () {
      await validateAcceptanceQr(currentAcceptanceQr);
    });

    $("btn-load-manual-qr").addEventListener("click", async function () {
      var val = $("manual-qr-input").value;
      if (await validateAcceptanceQr(val)) $("manual-qr-input").value = "";
    });

    $("qr-file-input").addEventListener("change", function (e) {
      var file = e.target.files && e.target.files[0];
      if (!file) return;
      var url = URL.createObjectURL(file);
      var img = new Image();
      img.onload = async function () {
        try {
          var c = document.createElement("canvas");
          c.width = img.width; c.height = img.height;
          var ctx = c.getContext("2d");
          ctx.drawImage(img, 0, 0);
          var idata = ctx.getImageData(0, 0, c.width, c.height);
          var res = window.TaiJsQrLib && window.TaiJsQrLib(idata.data, c.width, c.height, { inversionAttempts: "attemptBoth" });
          if (res && res.data) await validateAcceptanceQr(res.data);
          else setFeedback("No se detectó un QR válido en la imagen.", "warn");
        } finally {
          URL.revokeObjectURL(url);
          e.target.value = "";
        }
      };
      img.src = url;
    });

    $("cvv-form").addEventListener("submit", async function (e) {
      e.preventDefault();
      if (!session || !validatedQr) {
        setFeedback("Debes autenticar tu credencial y validar un QR de aceptación primero.", "warn");
        return;
      }

      var localTimestamp = new Date().toISOString();
      var nextSeq = offlineQueue.filter(function (q) { return q.packageId === validatedQr.packageId; }).length + 1;
      var delivererName = $("deliverer-name").value.trim().slice(0, 120);
      var receiverName = $("receiver-name").value.trim().slice(0, 120);
      var zone = $("zone-name").value.trim().slice(0, 120);
      var functionRole = $("function-role").value.trim().slice(0, 120);
      var observations = $("observations").value.trim().slice(0, 500);

      var sealed = await CryptoEngine.sealTransferEvent({
        packageId: validatedQr.packageId,
        eventType: validatedQr.eventType,
        delivererName: delivererName,
        receiverName: receiverName,
        zone: zone,
        functionRole: functionRole,
        acceptanceNonce: validatedQr.nonce,
        localTimestamp: localTimestamp,
        observations: observations,
        acceptanceProof: validatedQr.proof
      }, session);

      var item = {
        localId: "LOC_" + Date.now() + "_" + CryptoEngine.bytesToHex(crypto.getRandomValues(new Uint8Array(2))),
        eventId: sealed.eventId,
        packageId: validatedQr.packageId,
        packageCode: validatedQr.packageCode,
        eventType: validatedQr.eventType,
        delivererName: delivererName,
        receiverName: receiverName,
        zone: zone,
        functionRole: functionRole,
        observations: observations,
        acceptanceNonce: validatedQr.nonce,
        offlineSequence: nextSeq,
        deviceId: session.deviceId,
        localTimestamp: localTimestamp,
        sealStatus: $("seal-status").value,
        discrepancyNote: $("discrepancy-note").value.trim().slice(0, 400),
        cvvCiphertext: sealed.cvvCiphertext,
        cvvIv: sealed.cvvIv,
        cvvAuthTag: sealed.cvvAuthTag,
        csgSeal: sealed.csgSeal,
        acceptanceHash: validatedQr.acceptanceHash,
        acceptanceCryptoId: validatedQr.acceptanceCryptoId,
        receiverUid: validatedQr.receiverUid,
        receiverKeyId: validatedQr.proof ? validatedQr.proof.receiverKeyId : "",
        receiverSignature: validatedQr.proof ? validatedQr.proof.signatureB64u : "",
        proof: sealed.proof
      };

      offlineQueue.push(item);
      await saveEncryptedQueue();
      renderQueueAndAudit();

      validatedQr = null;
      $("btn-generate-cvv").disabled = true;
      $("validated-qr-banner").className = "alert";
      $("validated-qr-banner").textContent = "Captura y valida el QR de aceptación del receptor antes de generar el CVV.";
      acceptanceNonce = generateNonce();
      void renderAcceptanceQr();
      setFeedback("CVV " + sealed.eventId + " generado localmente con firma ECDSA de estación #" + session.stationKeyId + " y guardado en cola offline (Seq #" + nextSeq + ").", "ok");
    });

    $("btn-export-batch").addEventListener("click", function () {
      if (!session || offlineQueue.length === 0) return;
      var exportObj = {
        format: "tai-offline-batch-v1",
        exportedAt: new Date().toISOString(),
        operatorUid: session.operator.uid,
        operatorEmail: session.operator.email,
        deviceId: session.deviceId,
        stationKeyId: session.stationKeyId,
        stationPublicKeyB64u: session.stationPublicKeyB64u,
        stationCert: session.stationCert || null,
        events: offlineQueue
      };
      var blob = new Blob([JSON.stringify(exportObj, null, 2)], { type: "application/json" });
      var url = URL.createObjectURL(blob);
      var a = document.createElement("a");
      a.href = url;
      a.download = "tai-offline-batch-" + new Date().toISOString().slice(0, 10) + ".json";
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    });

    $("audit-event-select").addEventListener("change", renderAuditPreview);
    $("btn-verify-cvv").addEventListener("click", function () { verifySelectedCvv(false); });
    $("btn-tamper-cvv").addEventListener("click", function () { verifySelectedCvv(true); });
  })();
  </script>
</body>
</html>`;
}
