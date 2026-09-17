// CureSync AI parser backend — the ONE place the AI API key lives.
// The mobile app POSTs a handwriting PNG here; Gemini vision reads it and returns structured
// medicines. Keeping this server-side is mandatory: a key shipped inside the APK/IPA is
// trivially extractable.
import express from 'express';
import cors from 'cors';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// Load server/.env (GEMINI_API_KEY, PORT, GEMINI_MODEL) if present.
try {
  process.loadEnvFile(join(__dirname, '.env'));
} catch {
  try {
    process.loadEnvFile();
  } catch {}
}

const API_KEY = process.env.GEMINI_API_KEY || '';
const MODEL = process.env.GEMINI_MODEL || 'gemini-3.6-flash';

if (!API_KEY || API_KEY.includes('...') || API_KEY.includes('YOUR')) {
  console.error('\n⚠️  GEMINI_API_KEY is missing or still the placeholder.');
  console.error('   Get a free key at https://aistudio.google.com/apikey and put it in server/.env:');
  console.error('   GEMINI_API_KEY=AIza...\n');
}

const app = express();
app.use(cors());
app.use(express.json({ limit: '15mb' })); // base64 PNGs are large

// Gemini structured-output schema (uppercase types, no additionalProperties).
const SCHEMA = {
  type: 'OBJECT',
  properties: {
    medicines: {
      type: 'ARRAY',
      items: {
        type: 'OBJECT',
        properties: {
          name: { type: 'STRING' },
          dosage: { type: 'STRING' },
          duration: { type: 'STRING' },
          timing: { type: 'STRING' },
        },
        required: ['name', 'dosage', 'duration', 'timing'],
      },
    },
  },
  required: ['medicines'],
};

const SYSTEM =
  'You digitise handwritten prescriptions from Indian clinics. Read the image and extract each ' +
  'medicine. Use standard Indian brand spellings. Dosage is often written as 1-0-1 ' +
  '(morning-noon-night). Leave a field as an empty string rather than guessing when it is ' +
  'illegible or absent. Only include medicines you can actually read.';

const AUDIO_SCHEMA = {
  type: 'OBJECT',
  properties: {
    diagnosis: { type: 'STRING' },
    notes: { type: 'STRING' },
    labTests: { type: 'STRING' },
    systemCategory: { type: 'STRING' },
    followUpDate: { type: 'STRING' },
    medicines: {
      type: 'ARRAY',
      items: {
        type: 'OBJECT',
        properties: {
          name: { type: 'STRING' },
          dosage: { type: 'STRING' },
          duration: { type: 'STRING' },
          timing: { type: 'STRING' },
        },
        required: ['name', 'dosage', 'duration', 'timing'],
      },
    },
  },
  required: ['diagnosis', 'notes', 'labTests', 'systemCategory', 'followUpDate', 'medicines'],
};

const AUDIO_SYSTEM =
  'You are an expert AI clinical scribe for Indian clinics. Listen to this doctor-patient ambient consultation audio or doctor dictation. Extract the clinical diagnosis, notes/advice, recommended lab/diagnostic tests (e.g. CBC, LFT, Chest X-Ray), body system category (General, Respiratory, GI, Cardio, Derma, ENT, Ortho), follow-up date (YYYY-MM-DD format if mentioned, or empty string), and all prescribed medicines with dosage (e.g. 1-0-1), duration (e.g. 5 days), and timing (e.g. After food). Use standard Indian brand spellings.';

app.get('/health', (_req, res) => res.json({ ok: true, model: MODEL }));

app.post('/api/v1/prescriptions/parse', async (req, res) => {
  const { image, mimeType = 'image/png' } = req.body ?? {};
  if (!image || typeof image !== 'string') {
    return res.status(400).json({ error: 'image (base64) is required' });
  }
  try {
    const url = `https://generativelanguage.googleapis.com/v1beta/models/${MODEL}:generateContent`;
    const r = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'x-goog-api-key': API_KEY },
      body: JSON.stringify({
        systemInstruction: { parts: [{ text: SYSTEM }] },
        contents: [
          {
            parts: [
              { inlineData: { mimeType, data: image } },
              { text: 'Extract the medicines from this prescription.' },
            ],
          },
        ],
        generationConfig: { responseMimeType: 'application/json', responseSchema: SCHEMA },
      }),
    });

    const body = await r.json();
    if (!r.ok) {
      const detail = body?.error?.message || `Gemini HTTP ${r.status}`;
      console.error('[parse] gemini error:', r.status, detail);
      return res.status(502).json({ error: 'parse_failed', status: r.status, detail });
    }
    // responseMimeType=json → the model's text part is a JSON string matching SCHEMA.
    const text = body?.candidates?.[0]?.content?.parts?.[0]?.text ?? '{"medicines":[]}';
    res.json(JSON.parse(text));
  } catch (err) {
    const detail = err?.message || String(err);
    console.error('[parse] failed:', detail);
    res.status(502).json({ error: 'parse_failed', detail });
  }
});

app.post('/api/v1/prescriptions/parse-audio', async (req, res) => {
  const { audio, mimeType = 'audio/wav' } = req.body ?? {};
  if (!audio || typeof audio !== 'string') {
    return res.status(400).json({ error: 'audio (base64) is required' });
  }
  try {
    const url = `https://generativelanguage.googleapis.com/v1beta/models/${MODEL}:generateContent`;
    const r = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'x-goog-api-key': API_KEY },
      body: JSON.stringify({
        systemInstruction: { parts: [{ text: AUDIO_SYSTEM }] },
        contents: [
          {
            parts: [
              { inlineData: { mimeType, data: audio } },
              { text: 'Listen to the audio consultation and extract diagnosis, notes, follow-up date, and medicines.' },
            ],
          },
        ],
        generationConfig: { responseMimeType: 'application/json', responseSchema: AUDIO_SCHEMA },
      }),
    });

    const body = await r.json();
    if (!r.ok) {
      const detail = body?.error?.message || `Gemini HTTP ${r.status}`;
      console.error('[parse-audio] gemini error:', r.status, detail);
      return res.status(502).json({ error: 'parse_audio_failed', status: r.status, detail });
    }
    const text = body?.candidates?.[0]?.content?.parts?.[0]?.text ?? '{"diagnosis":"","notes":"","followUpDate":"","medicines":[]}';
    res.json(JSON.parse(text));
  } catch (err) {
    const detail = err?.message || String(err);
    console.error('[parse-audio] failed:', detail);
    res.status(502).json({ error: 'parse_audio_failed', detail });
  }
});

const port = process.env.PORT || 8787;
app.listen(port, () => console.log(`CureSync parser on :${port} (model: ${MODEL})`));

