export interface PickedDriveFile {
  id: string;
  name: string;
  mimeType: string;
  url: string;
  iconUrl?: string;
}

interface PickerDocument {
  id?: string;
  name?: string;
  mimeType?: string;
  url?: string;
  iconUrl?: string;
}

interface PickerCallbackData {
  action?: string;
  docs?: PickerDocument[];
}

interface PickerBuilderInstance {
  addView: (view: unknown) => PickerBuilderInstance;
  enableFeature?: (feature: unknown) => PickerBuilderInstance;
  setOAuthToken: (token: string) => PickerBuilderInstance;
  setCallback: (cb: (data: PickerCallbackData) => void) => PickerBuilderInstance;
  setOrigin: (origin: string) => PickerBuilderInstance;
  setLocale?: (locale: string) => PickerBuilderInstance;
  setTitle?: (title: string) => PickerBuilderInstance;
  build: () => { setVisible: (visible: boolean) => void };
}

interface GooglePickerNamespace {
  Action: {
    PICKED: string;
    CANCEL: string;
  };
  ViewId: {
    DOCS: unknown;
    SPREADSHEETS: unknown;
  };
  Feature?: {
    MULTISELECT_ENABLED: unknown;
  };
  PickerBuilder: new () => PickerBuilderInstance;
  DocsView: new (viewId?: unknown) => {
    setIncludeFolders?: (include: boolean) => unknown;
    setSelectFolderEnabled?: (enable: boolean) => unknown;
  };
  DocsUploadView: new () => unknown;
}

declare global {
  interface Window {
    gapi?: {
      load: (apiName: string, options: { callback: () => void; onerror?: () => void } | (() => void)) => void;
    };
    google?: {
      picker?: GooglePickerNamespace;
    };
  }
}

let pickerLoadPromise: Promise<GooglePickerNamespace> | null = null;

function loadGoogleApiScript(): Promise<void> {
  if (typeof window === 'undefined') {
    return Promise.reject(new Error('Google Picker requiere un navegador activo.'));
  }
  if (window.gapi) {
    return Promise.resolve();
  }

  return new Promise((resolve, reject) => {
    const existing = document.querySelector<HTMLScriptElement>(
      'script[src^="https://apis.google.com/js/api.js"]'
    );
    if (existing) {
      const startedAt = Date.now();
      const poll = () => {
        if (window.gapi) {
          resolve();
          return;
        }
        if (Date.now() - startedAt > 10000) {
          reject(new Error('Tiempo de espera agotado al cargar Google API.'));
          return;
        }
        window.setTimeout(poll, 100);
      };
      existing.addEventListener('error', () =>
        reject(new Error('No se pudo cargar apis.google.com/js/api.js.'))
      );
      poll();
      return;
    }

    const script = document.createElement('script');
    script.src = 'https://apis.google.com/js/api.js';
    script.async = true;
    script.defer = true;
    script.onload = () => resolve();
    script.onerror = () => reject(new Error('No se pudo cargar apis.google.com/js/api.js.'));
    document.head.appendChild(script);
  });
}

export async function ensureGooglePickerLoaded(): Promise<GooglePickerNamespace> {
  if (typeof window !== 'undefined' && window.google?.picker) {
    return window.google.picker;
  }
  if (pickerLoadPromise) {
    return pickerLoadPromise;
  }

  pickerLoadPromise = (async () => {
    await loadGoogleApiScript();
    if (!window.gapi) {
      throw new Error('La librería gapi no está disponible.');
    }

    return await new Promise<GooglePickerNamespace>((resolve, reject) => {
      window.gapi!.load('picker', {
        callback: () => {
          if (window.google?.picker) {
            resolve(window.google.picker);
          } else {
            pickerLoadPromise = null;
            reject(new Error('No se pudo inicializar google.picker.'));
          }
        },
        onerror: () => {
          pickerLoadPromise = null;
          reject(new Error('Error al cargar el módulo picker de Google.'));
        },
      });
    });
  })().catch((err) => {
    pickerLoadPromise = null;
    throw err;
  });

  return pickerLoadPromise;
}

function getSafeExternalUrl(raw?: string, fallbackId?: string): string {
  if (raw && raw.startsWith('https://')) {
    return raw;
  }
  if (fallbackId) {
    return `https://drive.google.com/file/d/${encodeURIComponent(fallbackId)}/view`;
  }
  return 'https://drive.google.com';
}

export async function openGooglePicker(options: {
  accessToken: string;
  mode: 'spreadsheets' | 'docs';
}): Promise<PickedDriveFile[]> {
  const pickerApi = await ensureGooglePickerLoaded();

  const pickerOrigin =
    window.location.ancestorOrigins && window.location.ancestorOrigins.length > 0
      ? window.location.ancestorOrigins[window.location.ancestorOrigins.length - 1]
      : window.location.origin;

  return new Promise<PickedDriveFile[]>((resolve) => {
    const builder = new pickerApi.PickerBuilder()
      .setOAuthToken(options.accessToken)
      .setOrigin(pickerOrigin)
      .setCallback((data: PickerCallbackData) => {
        if (data.action === pickerApi.Action.PICKED && Array.isArray(data.docs)) {
          const mapped: PickedDriveFile[] = data.docs
            .filter((doc): doc is PickerDocument & { id: string } => Boolean(doc.id))
            .map((doc) => ({
              id: doc.id,
              name: doc.name || 'Archivo sin nombre',
              mimeType: doc.mimeType || 'application/octet-stream',
              url: getSafeExternalUrl(doc.url, doc.id),
              iconUrl:
                doc.iconUrl && doc.iconUrl.startsWith('https://') ? doc.iconUrl : undefined,
            }));
          resolve(mapped);
          return;
        }
        if (data.action === pickerApi.Action.CANCEL) {
          resolve([]);
        }
      });

    if (builder.setLocale) {
      builder.setLocale('es');
    }

    if (options.mode === 'spreadsheets') {
      if (builder.setTitle) {
        builder.setTitle('Seleccionar hoja de Google Sheets');
      }
      const sheetsView = new pickerApi.DocsView(pickerApi.ViewId.SPREADSHEETS);
      builder.addView(sheetsView);
    } else {
      if (builder.setTitle) {
        builder.setTitle('Seleccionar o subir documentos de evidencia TAI');
      }
      builder.addView(pickerApi.ViewId.DOCS);
      builder.addView(new pickerApi.DocsUploadView());
      if (pickerApi.Feature?.MULTISELECT_ENABLED && builder.enableFeature) {
        builder.enableFeature(pickerApi.Feature.MULTISELECT_ENABLED);
      }
    }

    const picker = builder.build();
    picker.setVisible(true);
  });
}
