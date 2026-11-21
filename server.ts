import express from 'express';
import crypto from 'crypto';
import path from 'path';
import { fileURLToPath } from 'url';
import dotenv from 'dotenv';
import { GoogleGenAI } from '@google/genai';

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const PORT = 3000;

// Derive a 32-byte AES-256-GCM sealing key from env or ephemeral CSPRNG fallback in memory
const RAW_SECRET = process.env.TAI_SEALING_SECRET;
const SEALING_KEY: Buffer = RAW_SECRET && RAW_SECRET.length >= 16
  ? crypto.createHash('sha256').update(RAW_SECRET).digest()
  : crypto.randomBytes(32);

const ai = new GoogleGenAI({
  apiKey: process.env.GEMINI_API_KEY,
  httpOptions: {
    headers: {
      'User-Agent': 'aistudio-build',
    },
  },
});

function computeCsgSeal(params: {
  packageId: string;
  eventId: string;
  eventType: string;
  acceptanceNonce: string;
  authTag: string;
}): string {
  const canonical = [
    params.packageId,
    params.eventId,
    params.eventType,
    params.acceptanceNonce,
    params.authTag,
  ].join('|');
  return crypto.createHmac('sha256', SEALING_KEY).update(canonical).digest('hex');
}

async function startServer() {
  const app = express();
  app.use(express.json({ limit: '1mb' }));

  app.get('/api/health', (_req, res) => {
    res.json({ status: 'ok', service: 'tai-ypf-pilot' });
  });

  // AES-256-GCM + CSG Sealing endpoint for CVV issuance
  app.post('/api/crypto/seal', (req, res) => {
    try {
      const {
        packageId,
        eventId,
        eventType,
        delivererName,
        receiverName,
        zone,
        functionRole,
        acceptanceNonce,
        localTimestamp,
        observations,
      } = req.body ?? {};

      if (
        typeof packageId !== 'string' || !packageId.trim() ||
        typeof eventId !== 'string' || !eventId.trim() ||
        typeof eventType !== 'string' || !eventType.trim() ||
        typeof delivererName !== 'string' || !delivererName.trim() ||
        typeof receiverName !== 'string' || !receiverName.trim() ||
        typeof acceptanceNonce !== 'string' || !acceptanceNonce.trim()
      ) {
        return res.status(400).json({ error: 'Faltan campos obligatorios para emitir el CVV.' });
      }

      const payload = {
        v: 'TAI-CVV-1',
        packageId: packageId.slice(0, 64),
        eventId: eventId.slice(0, 128),
        eventType: eventType.slice(0, 40),
        delivererName: delivererName.slice(0, 120),
        receiverName: receiverName.slice(0, 120),
        zone: String(zone ?? 'Centro Logístico Buenos Aires').slice(0, 120),
        functionRole: String(functionRole ?? 'Operador Logístico').slice(0, 120),
        acceptanceNonce: acceptanceNonce.slice(0, 128),
        localTimestamp: String(localTimestamp ?? new Date().toISOString()).slice(0, 64),
        observations: String(observations ?? '').slice(0, 500),
      };

      const iv = crypto.randomBytes(12);
      const cipher = crypto.createCipheriv('aes-256-gcm', SEALING_KEY, iv);
      // Bind packageId & eventId as Additional Authenticated Data (AAD)
      cipher.setAAD(Buffer.from(`${payload.packageId}:${payload.eventId}`, 'utf8'));

      const plaintext = JSON.stringify(payload);
      const encrypted = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
      const authTag = cipher.getAuthTag();

      const ciphertextHex = encrypted.toString('hex');
      const ivHex = iv.toString('hex');
      const authTagHex = authTag.toString('hex');
      const csgSeal = computeCsgSeal({
        packageId: payload.packageId,
        eventId: payload.eventId,
        eventType: payload.eventType,
        acceptanceNonce: payload.acceptanceNonce,
        authTag: authTagHex,
      });

      return res.json({
        ciphertext: ciphertextHex,
        iv: ivHex,
        authTag: authTagHex,
        csgSeal,
        algorithm: 'AES-256-GCM + CSG-HMAC-SHA256',
      });
    } catch (err) {
      console.error('Error sealing CVV:', err);
      return res.status(500).json({ error: 'No se pudo generar el sellado criptográfico del CVV.' });
    }
  });

  // AES-256-GCM + CSG Verification & Tamper Detection endpoint
  app.post('/api/crypto/verify', (req, res) => {
    try {
      const {
        ciphertext,
        iv,
        authTag,
        csgSeal,
        packageId,
        eventId,
        eventType,
        acceptanceNonce,
      } = req.body ?? {};

      if (
        typeof ciphertext !== 'string' ||
        typeof iv !== 'string' ||
        typeof authTag !== 'string' ||
        typeof csgSeal !== 'string' ||
        typeof packageId !== 'string' ||
        typeof eventId !== 'string' ||
        typeof eventType !== 'string' ||
        typeof acceptanceNonce !== 'string'
      ) {
        return res.status(400).json({ valid: false, csgStatus: 'INVALIDATED_TAMPERED', reason: 'Parámetros de verificación incompletos.' });
      }

      const expectedSeal = computeCsgSeal({
        packageId,
        eventId,
        eventType,
        acceptanceNonce,
        authTag,
      });

      const sealMatch =
        expectedSeal.length === csgSeal.length &&
        crypto.timingSafeEqual(Buffer.from(expectedSeal, 'utf8'), Buffer.from(csgSeal, 'utf8'));

      if (!sealMatch) {
        return res.json({
          valid: false,
          csgStatus: 'OUT_OF_FLOW',
          reason: 'El sello CSG no coincide con la secuencia o el paquete autorizado. Documento invalidado; evidencia maestra preservada.',
        });
      }

      const decipher = crypto.createDecipheriv(
        'aes-256-gcm',
        SEALING_KEY,
        Buffer.from(iv, 'hex')
      );
      decipher.setAAD(Buffer.from(`${packageId}:${eventId}`, 'utf8'));
      decipher.setAuthTag(Buffer.from(authTag, 'hex'));

      const decrypted = Buffer.concat([
        decipher.update(Buffer.from(ciphertext, 'hex')),
        decipher.final(),
      ]);
      const parsed = JSON.parse(decrypted.toString('utf8'));

      return res.json({
        valid: true,
        csgStatus: 'VERIFIED',
        decryptedPayload: parsed,
        reason: 'Integridad AES-256-GCM y sello CSG verificados correctamente.',
      });
    } catch {
      return res.json({
        valid: false,
        csgStatus: 'INVALIDATED_TAMPERED',
        reason: 'Fallo de autenticación GCM (AuthTag inválido o texto cifrado alterado). CSG invalida el documento.',
      });
    }
  });

  // Gemini 4 Hydrogen + Google Maps Grounding endpoint
  app.post('/api/maps-grounding', async (req, res) => {
    try {
      if (!process.env.GEMINI_API_KEY) {
        return res.status(503).json({
          error: 'GEMINI_API_KEY no está configurada en el servidor. Configura la clave en Settings > Secrets.',
        });
      }

      const { query, latitude, longitude } = req.body ?? {};
      if (typeof query !== 'string' || !query.trim() || query.length > 400) {
        return res.status(400).json({ error: 'Consulta geográfica inválida.' });
      }

      const lat = typeof latitude === 'number' && Number.isFinite(latitude) ? latitude : -34.6395;
      const lng = typeof longitude === 'number' && Number.isFinite(longitude) ? longitude : -58.3526;

      const response = await ai.models.generateContent({
        model: 'gemini-4-hydrogen',
        contents: `Eres un especialista en logística energética en Argentina. Responde en español de forma clara y operativa sobre ubicaciones, centros logísticos, accesos viales y zonas industriales relevantes para: ${query.trim()}`,
        config: {
          tools: [{ googleMaps: {} }],
          toolConfig: {
            retrievalConfig: {
              latLng: {
                latitude: lat,
                longitude: lng,
              },
            },
          },
        },
      });

      const chunks = response.candidates?.[0]?.groundingMetadata?.groundingChunks ?? [];
      const places = chunks
        .filter((chunk) => Boolean(chunk.maps))
        .map((chunk) => {
          const mapsData = chunk.maps as {
            uri?: string;
            title?: string;
            placeId?: string;
            placeAnswerSources?: {
              reviewSnippets?: Array<{ uri?: string; title?: string; authorAttribution?: { displayName?: string } }>;
            };
          };
          return {
            title: mapsData.title ?? 'Ubicación en Google Maps',
            uri: mapsData.uri ?? '',
            placeId: mapsData.placeId ?? '',
            reviewSnippets: mapsData.placeAnswerSources?.reviewSnippets ?? [],
          };
        })
        .filter((p) => Boolean(p.uri));

      return res.json({
        text: response.text ?? '',
        places,
        coordinatesUsed: { latitude: lat, longitude: lng },
      });
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : 'Error al consultar Google Maps Grounding.';
      console.error('Maps Grounding error:', err);
      return res.status(500).json({ error: message });
    }
  });

  if (process.env.NODE_ENV !== 'production') {
    const { createServer: createViteServer } = await import('vite');
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.resolve(__dirname, 'dist');
    app.use(express.static(distPath));
    app.get('*', (_req, res) => {
      res.sendFile(path.join(distPath, 'index.html'));
    });
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`TAI Pilot Server running on http://0.0.0.0:${PORT}`);
  });
}

startServer();
