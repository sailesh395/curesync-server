// CureSync AI parser backend — the ONE place the AI API key lives.
// The mobile app POSTs a handwriting PNG here; Gemini vision reads it and returns structured
// medicines. Keeping this server-side is mandatory: a key shipped inside the APK/IPA is
// trivially extractable.
import express from 'express';
import cors from 'cors';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { requestOtp, verifyOtp } from './otp.js';

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

// Shared secret. The app sends it as x-app-key; without a match we reject so a leaked public URL
// can't burn the Gemini quota. Unset (local dev) → the gate is open.
// ponytail: a secret baked into the APK is extractable by a determined attacker; this stops
// casual abuse only. Upgrade path: real per-user auth when there are accounts.
const APP_KEY = process.env.APP_KEY || '';

function requireAppKey(req, res, next) {
  if (!APP_KEY) return next();
  if (req.get('x-app-key') === APP_KEY) return next();
  return res.status(401).json({ error: 'unauthorized' });
}

if (!API_KEY || API_KEY.includes('...') || API_KEY.includes('YOUR')) {
  console.error('\n⚠️  GEMINI_API_KEY is missing or still the placeholder.');
  console.error('   Get a free key at https://aistudio.google.com/apikey and put it in server/.env:');
  console.error('   GEMINI_API_KEY=AIza...\n');
}

// --- Phone-OTP login (server-side; the client never decides "code correct") ---
const otpStore = new Map(); // phone -> { hash, expiresAt, attempts, sentAt }

// 10-digit Indian subscriber number (drop +91 / leading 0). Mirrors the app's validate.ts.
function normalizePhone(raw) {
  let d = String(raw ?? '').replace(/\D/g, '');
  if (d.length === 12 && d.startsWith('91')) d = d.slice(2);
  if (d.length === 11 && d.startsWith('0')) d = d.slice(1);
  return d;
}

// Deliver the code. With MSG91_AUTH_KEY set → real SMS; otherwise dev mode (log + let the route
// echo the code so the pilot works before an SMS account exists). Throws only when a real provider
// is configured and the send fails, so we never silently drop a production OTP.
async function sendSms(phone, code) {
  const key = process.env.MSG91_AUTH_KEY;
  if (!key) {
    console.log(`[dev-otp] +91${phone} -> ${code}`);
    return { dev: true };
  }
  const r = await fetch('https://control.msg91.com/api/v5/flow', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', authkey: key },
    body: JSON.stringify({
      template_id: process.env.MSG91_TEMPLATE_ID,
      recipients: [{ mobiles: `91${phone}`, otp: code }],
    }),
  });
  if (!r.ok) throw new Error(`msg91 ${r.status}`);
  return { dev: false };
}

const app = express();
app.use(cors());
app.use(express.json({ limit: '15mb' })); // base64 PNGs are large

app.post('/api/v1/auth/request-otp', requireAppKey, async (req, res) => {
  const phone = normalizePhone(req.body?.phone);
  if (!/^[6-9]\d{9}$/.test(phone)) return res.status(400).json({ error: 'bad_phone' });
  const r = requestOtp(otpStore, phone);
  if (!r.ok) return res.status(429).json({ error: r.error, retryIn: r.retryIn });
  try {
    const sent = await sendSms(phone, r.code);
    // devCode is returned ONLY in dev mode (no SMS provider) so testers can log in without SMS.
    res.json({ ok: true, expiresIn: r.expiresIn, ...(sent.dev ? { devCode: r.code } : {}) });
  } catch (e) {
    otpStore.delete(phone);
    console.error('[request-otp] sms failed:', e?.message || e);
    res.status(502).json({ error: 'sms_failed' });
  }
});

app.post('/api/v1/auth/verify-otp', requireAppKey, (req, res) => {
  const phone = normalizePhone(req.body?.phone);
  const r = verifyOtp(otpStore, phone, req.body?.code);
  if (!r.ok) return res.status(401).json({ error: r.error });
  // Opaque session marker. ponytail: the AI routes are gated by x-app-key, not this token, so it
  // needs no server-side verification yet; issue a signed JWT + verify it when endpoints go per-user.
  const token = `otp_${phone}_${crypto.randomBytes(16).toString('hex')}`;
  res.json({ ok: true, token, phone });
});

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

app.post('/api/v1/prescriptions/parse', requireAppKey, async (req, res) => {
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

app.post('/api/v1/prescriptions/parse-audio', requireAppKey, async (req, res) => {
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

