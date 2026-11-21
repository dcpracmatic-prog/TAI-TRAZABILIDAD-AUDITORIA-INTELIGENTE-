export interface SheetTabInfo {
  sheetId: number;
  title: string;
}

export interface SpreadsheetMetadata {
  spreadsheetId: string;
  title: string;
  spreadsheetUrl: string;
  tabs: SheetTabInfo[];
}

export async function createTaiAuditSpreadsheet(
  accessToken: string,
  title: string
): Promise<SpreadsheetMetadata> {
  const res = await fetch('https://sheets.googleapis.com/v4/spreadsheets', {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${accessToken}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      properties: {
        title: title.trim() || 'TAI Piloto YPF — Bitácora de Trazabilidad',
        locale: 'es_AR',
      },
      sheets: [
        { properties: { title: 'Paquetes' } },
        { properties: { title: 'Eventos_CVV' } },
        { properties: { title: 'Auditoria_Maestra' } },
      ],
    }),
  });

  if (!res.ok) {
    const errText = await res.text();
    throw new Error(`No se pudo crear la hoja de Google Sheets (${res.status}): ${errText}`);
  }

  const data = await res.json();
  const spreadsheetId = data.spreadsheetId as string;

  // Write initial headers to the 3 tabs
  await fetch(
    `https://sheets.googleapis.com/v4/spreadsheets/${spreadsheetId}/values:batchUpdate`,
    {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${accessToken}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        valueInputOption: 'USER_ENTERED',
        data: [
          {
            range: 'Paquetes!A1:K1',
            values: [
              [
                'ID Paquete',
                'Código',
                'FROM (Origen)',
                'Área Destino',
                'Zona BA',
                'Contenido',
                'Cantidad',
                'Unidad',
                'Identificación',
                'Estado Cierre',
                'Estado Ciclo',
              ],
            ],
          },
          {
            range: 'Eventos_CVV!A1:K1',
            values: [
              [
                'ID Evento',
                'ID Paquete',
                'Tipo Evento',
                'Quien Entrega',
                'Quien Recibe',
                'Zona',
                'Función',
                'Captura Offline',
                'Nonce Aceptación',
                'Estado CVV / CSG',
                'Sello CSG (Prefijo)',
              ],
            ],
          },
          {
            range: 'Auditoria_Maestra!A1:F1',
            values: [
              [
                'ID Registro',
                'ID Paquete',
                'Acción',
                'Severidad',
                'Detalle',
                'Operador',
              ],
            ],
          },
        ],
      }),
    }
  );

  return {
    spreadsheetId,
    title: data.properties?.title ?? title,
    spreadsheetUrl: data.spreadsheetUrl ?? `https://docs.google.com/spreadsheets/d/${spreadsheetId}`,
    tabs: (data.sheets ?? []).map((s: { properties?: { sheetId?: number; title?: string } }) => ({
      sheetId: s.properties?.sheetId ?? 0,
      title: s.properties?.title ?? 'Hoja',
    })),
  };
}

export async function getSpreadsheetMetadata(
  accessToken: string,
  spreadsheetIdInput: string
): Promise<SpreadsheetMetadata> {
  const extracted = extractSpreadsheetId(spreadsheetIdInput);
  const res = await fetch(
    `https://sheets.googleapis.com/v4/spreadsheets/${encodeURIComponent(extracted)}?fields=spreadsheetId,spreadsheetUrl,properties.title,sheets.properties(sheetId,title)`,
    {
      headers: {
        Authorization: `Bearer ${accessToken}`,
      },
    }
  );

  if (!res.ok) {
    const errText = await res.text();
    throw new Error(`No se pudo leer la hoja de cálculo (${res.status}): ${errText}`);
  }

  const data = await res.json();
  return {
    spreadsheetId: data.spreadsheetId,
    title: data.properties?.title ?? 'Hoja de Cálculo',
    spreadsheetUrl: data.spreadsheetUrl ?? `https://docs.google.com/spreadsheets/d/${data.spreadsheetId}`,
    tabs: (data.sheets ?? []).map((s: { properties?: { sheetId?: number; title?: string } }) => ({
      sheetId: s.properties?.sheetId ?? 0,
      title: s.properties?.title ?? 'Hoja',
    })),
  };
}

export async function readSheetRange(
  accessToken: string,
  spreadsheetId: string,
  sheetTitle: string
): Promise<string[][]> {
  const safeRange = `'${sheetTitle.replace(/'/g, "''")}'!A1:L50`;
  const res = await fetch(
    `https://sheets.googleapis.com/v4/spreadsheets/${encodeURIComponent(spreadsheetId)}/values/${encodeURIComponent(safeRange)}`,
    {
      headers: {
        Authorization: `Bearer ${accessToken}`,
      },
    }
  );

  if (!res.ok) {
    const errText = await res.text();
    throw new Error(`Error al leer rango ${sheetTitle} (${res.status}): ${errText}`);
  }

  const data = await res.json();
  return (data.values as string[][] | undefined) ?? [];
}

export async function appendRowsToSheet(
  accessToken: string,
  spreadsheetId: string,
  sheetTitle: string,
  rows: Array<Array<string | number | boolean>>
): Promise<{ updatedRows: number }> {
  const safeRange = `'${sheetTitle.replace(/'/g, "''")}'!A1`;
  const res = await fetch(
    `https://sheets.googleapis.com/v4/spreadsheets/${encodeURIComponent(spreadsheetId)}/values/${encodeURIComponent(safeRange)}:append?valueInputOption=USER_ENTERED&insertDataOption=INSERT_ROWS`,
    {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${accessToken}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        values: rows,
      }),
    }
  );

  if (!res.ok) {
    const errText = await res.text();
    throw new Error(`Error al escribir en Google Sheets (${res.status}): ${errText}`);
  }

  const data = await res.json();
  return {
    updatedRows: data.updates?.updatedRows ?? rows.length,
  };
}

export function extractSpreadsheetId(input: string): string {
  const trimmed = input.trim();
  const match = trimmed.match(/\/spreadsheets\/d\/([a-zA-Z0-9-_]+)/);
  if (match && match[1]) {
    return match[1];
  }
  return trimmed;
}
