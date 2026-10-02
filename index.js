// CureSync AI parser backend — the ONE place the AI API key lives.
// The mobile app POSTs a handwriting PNG here; Gemini vision reads it and returns structured
// medicines. Keeping this server-side is mandatory: a key shipped inside the APK/IPA is
// trivially extractable.
import express from 'express';
import cors from 'cors';
import crypto from 'node:crypto';
import pg from 'pg';
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

// --- Supabase Postgres (appointments). Lazy pool; booking routes 503 if it isn't configured, so
// the AI/OTP server still boots without a DB. ---
let _pool = null;
function db() {
  if (_pool) return _pool;
  const url = process.env.SUPABASE_DB_URL;
  if (!url) return null;
  // ponytail: TLS on, CA verification relaxed (the Supabase pooler cert isn't in Node's default
  // trust store). Traffic is encrypted; upgrade to pin Supabase's CA (ssl.ca) for full verification.
  _pool = new pg.Pool({ connectionString: url, ssl: { rejectUnauthorized: false }, max: 4 });
  return _pool;
}
function requireDb(req, res, next) {
  if (!db()) return res.status(503).json({ error: 'appointments_not_configured' });
  next();
}

// Idempotent schema migrations, run once at startup (service-role can ALTER). Keeps the live DB in
// sync without a manual SQL step for each small change.
async function migrate() {
  const pool = db();
  if (!pool) return;
  try {
    await pool.query('alter table clinics add column if not exists maps_link text');
    console.log('[migrate] clinics up to date');
  } catch (e) {
    console.error('[migrate] ', e.message);
  }
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

// --- Email-OTP login (same OTP core, keyed by email; separate store from phone) ---
const emailOtpStore = new Map();
const isEmail = (e) => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(String(e ?? '').trim());

// Deliver the code by email. With RESEND_API_KEY set → real email via Resend; else dev mode (log +
// let the route echo the code so the pilot works before an email provider exists).
async function sendEmail(email, code) {
  const key = process.env.RESEND_API_KEY;
  if (!key) {
    console.log(`[dev-otp] ${email} -> ${code}`);
    return { dev: true };
  }
  const r = await fetch('https://api.resend.com/emails', {
    method: 'POST',
    headers: { Authorization: `Bearer ${key}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({
      from: process.env.RESEND_FROM || 'CureSync <onboarding@resend.dev>',
      to: [email],
      subject: 'Your CureSync verification code',
      html: `<p>Your CureSync code is <b style="font-size:20px">${code}</b></p><p>It is valid for 5 minutes. If you didn't request it, ignore this email.</p>`,
    }),
  });
  if (!r.ok) throw new Error(`resend ${r.status}`);
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

app.post('/api/v1/auth/request-email-otp', requireAppKey, async (req, res) => {
  const email = String(req.body?.email ?? '').trim().toLowerCase();
  if (!isEmail(email)) return res.status(400).json({ error: 'bad_email' });
  const r = requestOtp(emailOtpStore, email);
  if (!r.ok) return res.status(429).json({ error: r.error, retryIn: r.retryIn });
  try {
    const sent = await sendEmail(email, r.code);
    res.json({ ok: true, expiresIn: r.expiresIn, ...(sent.dev ? { devCode: r.code } : {}) });
  } catch (e) {
    emailOtpStore.delete(email);
    console.error('[request-email-otp] send failed:', e?.message || e);
    res.status(502).json({ error: 'email_failed' });
  }
});

app.post('/api/v1/auth/verify-email-otp', requireAppKey, (req, res) => {
  const email = String(req.body?.email ?? '').trim().toLowerCase();
  const r = verifyOtp(emailOtpStore, email, req.body?.code);
  if (!r.ok) return res.status(401).json({ error: r.error });
  const token = `otp_${email}_${crypto.randomBytes(16).toString('hex')}`;
  res.json({ ok: true, token, email });
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
    labTests: { type: 'STRING' }, // comma-separated lab/diagnostic tests written on the pad; '' if none
  },
  required: ['medicines', 'labTests'],
};

const SYSTEM =
  'You digitise handwritten prescriptions from Indian clinics. Read the image and extract each ' +
  'medicine. Use standard Indian brand spellings. Dosage is often written as 1-0-1 ' +
  '(morning-noon-night). Also extract any lab or diagnostic tests written on the pad (e.g. CBC, ' +
  'LFT, KFT, Lipid Profile, Chest X-Ray, USG) into labTests as a comma-separated string; use "" ' +
  'if none are written. Leave a field as an empty string rather than guessing when it is ' +
  'illegible or absent. Only include medicines and tests you can actually read.';

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
  'You are an expert AI clinical scribe for Indian clinics. Listen to this doctor-patient ambient consultation audio or doctor dictation. Extract the clinical diagnosis, notes/advice, recommended lab/diagnostic tests (e.g. CBC, LFT, Chest X-Ray), body system category (General, Respiratory, GI, Cardio, Derma, ENT, Ortho), follow-up date (YYYY-MM-DD format if mentioned, or empty string), and all prescribed medicines with dosage (e.g. 1-0-1), duration (e.g. 5 days), and timing (e.g. After food). Use standard Indian brand spellings. The consultation may be in Telugu, Hindi, or any Indian language mixed with English drug names — understand it regardless and always return the fields in English. IMPORTANT: never invent a dosage, duration, or timing the doctor did not actually say — leave that field as an empty string instead of guessing.';

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
    const text = body?.candidates?.[0]?.content?.parts?.[0]?.text ?? '{"medicines":[],"labTests":""}';
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

// ===================== Appointments (OPD token queue) =====================

// Diagnostic: confirms the DB connection and returns the exact error if it fails. Safe to keep.
app.get('/api/v1/dbcheck', requireAppKey, async (req, res) => {
  const pool = db();
  if (!pool) return res.json({ configured: false });
  try {
    const r = await pool.query('select current_user, current_database()');
    res.json({ ok: true, user: r.rows[0].current_user, db: r.rows[0].current_database });
  } catch (e) {
    res.json({ ok: false, detail: e.message, code: e.code });
  }
});

// Race-safe next-token insert: concurrent books may compute the same MAX+1, hitting the
// unique(clinic_id, booking_date, token_number) constraint (23505) — retry a few times.
async function bookToken(pool, clinicId, name, phone) {
  for (let i = 0; i < 6; i++) {
    try {
      const r = await pool.query(
        `insert into bookings (clinic_id, token_number, patient_name, patient_phone)
         values ($1, (select coalesce(max(token_number),0)+1 from bookings
                      where clinic_id=$1 and booking_date=current_date), $2, $3)
         returning token_number`,
        [clinicId, name, phone || null],
      );
      return r.rows[0].token_number;
    } catch (e) {
      if (e.code === '23505') continue; // token taken by a concurrent book → retry
      throw e;
    }
  }
  throw new Error('token_contention');
}

// Doctor: create or update their clinic (one per doctor in v1).
app.post('/api/v1/clinics', requireAppKey, requireDb, async (req, res) => {
  const { doctorKey, name, address, phone, openHours, avgMinutes, mapsLink } = req.body ?? {};
  if (!doctorKey || !name) return res.status(400).json({ error: 'doctorKey_and_name_required' });
  const avg = Number.isFinite(+avgMinutes) && +avgMinutes > 0 ? Math.min(60, +avgMinutes) : 8;
  try {
    const ex = await db().query('select id from clinics where doctor_key=$1 limit 1', [doctorKey]);
    const vals = [name, address || null, phone || null, openHours || null, avg, mapsLink || null];
    const r = ex.rows[0]
      ? await db().query(
          `update clinics set name=$1,address=$2,phone=$3,open_hours=$4,avg_minutes_per_patient=$5,maps_link=$6,updated_at=now()
           where id=$7 returning *`, [...vals, ex.rows[0].id])
      : await db().query(
          `insert into clinics (name,address,phone,open_hours,avg_minutes_per_patient,maps_link,doctor_key)
           values ($1,$2,$3,$4,$5,$6,$7) returning *`, [...vals, doctorKey]);
    res.json({ clinic: r.rows[0] });
  } catch (e) { console.error('[clinics] ', e.message); res.status(500).json({ error: 'db_error' }); }
});

// Doctor: fetch their clinic.
app.get('/api/v1/my-clinic', requireAppKey, requireDb, async (req, res) => {
  const r = await db().query('select * from clinics where doctor_key=$1 limit 1', [String(req.query.doctorKey ?? '')]);
  res.json({ clinic: r.rows[0] ?? null });
});

// Doctor: advance the queue to the next token (marks the previous one done).
app.post('/api/v1/clinics/:id/advance', requireAppKey, requireDb, async (req, res) => {
  try {
    const r = await db().query('update clinics set now_serving=now_serving+1, updated_at=now() where id=$1 returning now_serving', [req.params.id]);
    if (!r.rows[0]) return res.status(404).json({ error: 'no_clinic' });
    await db().query(`update bookings set status='done' where clinic_id=$1 and booking_date=current_date and token_number < $2 and status='waiting'`, [req.params.id, r.rows[0].now_serving]);
    res.json({ now_serving: r.rows[0].now_serving });
  } catch (e) { console.error('[advance] ', e.message); res.status(500).json({ error: 'db_error' }); }
});

// Doctor: today's bookings (with patient names) for the queue screen.
app.get('/api/v1/clinics/:id/bookings', requireAppKey, requireDb, async (req, res) => {
  const r = await db().query(
    `select token_number, patient_name, patient_phone, status from bookings
     where clinic_id=$1 and booking_date=current_date order by token_number`, [req.params.id]);
  res.json({ bookings: r.rows });
});

// --- Public (patient-facing; no app key) ---

// Public clinic info + live queue summary (no patient PII).
app.get('/api/v1/clinics/:id', requireDb, async (req, res) => {
  try {
    const c = await db().query('select id,name,address,open_hours,maps_link,is_accepting,now_serving,avg_minutes_per_patient from clinics where id=$1', [req.params.id]);
    if (!c.rows[0]) return res.status(404).json({ error: 'no_clinic' });
    const w = await db().query(`select count(*)::int n from bookings where clinic_id=$1 and booking_date=current_date and status='waiting'`, [req.params.id]);
    res.json({ clinic: c.rows[0], waiting: w.rows[0].n });
  } catch (e) { console.error('[clinic get] ', e.message); res.status(500).json({ error: 'db_error' }); }
});

// Public: book a token.
app.post('/api/v1/clinics/:id/book', requireDb, async (req, res) => {
  const { patientName, patientPhone } = req.body ?? {};
  if (!patientName || String(patientName).trim().length < 2) return res.status(400).json({ error: 'name_required' });
  try {
    const c = await db().query('select now_serving, is_accepting, avg_minutes_per_patient from clinics where id=$1', [req.params.id]);
    if (!c.rows[0]) return res.status(404).json({ error: 'no_clinic' });
    if (!c.rows[0].is_accepting) return res.status(409).json({ error: 'not_accepting' });
    const token = await bookToken(db(), req.params.id, String(patientName).trim(), patientPhone);
    const ahead = Math.max(0, token - c.rows[0].now_serving - 1);
    res.json({ token_number: token, now_serving: c.rows[0].now_serving, ahead, est_minutes: ahead * c.rows[0].avg_minutes_per_patient });
  } catch (e) { console.error('[book] ', e.message); res.status(500).json({ error: 'db_error' }); }
});

// Public: live queue status (for the patient to poll their position).
app.get('/api/v1/clinics/:id/queue', requireDb, async (req, res) => {
  const c = await db().query('select now_serving, is_accepting from clinics where id=$1', [req.params.id]);
  if (!c.rows[0]) return res.status(404).json({ error: 'no_clinic' });
  res.json({ now_serving: c.rows[0].now_serving, is_accepting: c.rows[0].is_accepting });
});

// Public booking web page (the QR target). No app install needed.
// Patient booking page strings — English / Telugu / Hindi (patients in villages read te/hi, not en).
const BOOK_STR = {
  en: { pageTitle: 'Book appointment · CureSync', title: 'Book appointment', name: 'Your name', namePh: 'e.g. Ramesh Kumar', phone: 'Mobile (optional)', getToken: 'Get my token', yourToken: 'Your token', keepOpen: 'Keep this page open — your position updates automatically.', powered: 'Powered by CureSync', directions: '📍 Get directions', notFound: 'Clinic not found.', notAccepting: ' — not accepting bookings right now', enterName: 'Please enter your name.', bookFail: 'Could not book. Please try again.', next: 'You are next!', ahead: '{n} patient(s) ahead · now serving #{m}', loading: 'Loading…' },
  te: { pageTitle: 'అపాయింట్‌మెంట్ బుక్ చేయండి · CureSync', title: 'అపాయింట్‌మెంట్ బుక్ చేయండి', name: 'మీ పేరు', namePh: 'ఉదా. రమేష్ కుమార్', phone: 'మొబైల్ (ఐచ్ఛికం)', getToken: 'నా టోకెన్ పొందండి', yourToken: 'మీ టోకెన్', keepOpen: 'ఈ పేజీని తెరిచి ఉంచండి — మీ స్థానం దానంతటదే నవీకరించబడుతుంది.', powered: 'CureSync ద్వారా', directions: '📍 దారి చూడండి', notFound: 'క్లినిక్ కనుగొనబడలేదు.', notAccepting: ' — ప్రస్తుతం బుకింగ్‌లు స్వీకరించడం లేదు', enterName: 'దయచేసి మీ పేరు నమోదు చేయండి.', bookFail: 'బుక్ చేయడం సాధ్యపడలేదు. దయచేసి మళ్లీ ప్రయత్నించండి.', next: 'మీరే తదుపరి!', ahead: 'మీకు ముందు {n} మంది · ప్రస్తుతం #{m} సేవలో', loading: 'లోడ్ అవుతోంది…' },
  hi: { pageTitle: 'अपॉइंटमेंट बुक करें · CureSync', title: 'अपॉइंटमेंट बुक करें', name: 'आपका नाम', namePh: 'जैसे रमेश कुमार', phone: 'मोबाइल (वैकल्पिक)', getToken: 'मेरा टोकन लें', yourToken: 'आपका टोकन', keepOpen: 'इस पेज को खुला रखें — आपकी स्थिति अपने आप अपडेट होती रहती है।', powered: 'CureSync द्वारा संचालित', directions: '📍 रास्ता देखें', notFound: 'क्लिनिक नहीं मिला।', notAccepting: ' — अभी बुकिंग स्वीकार नहीं की जा रही', enterName: 'कृपया अपना नाम दर्ज करें।', bookFail: 'बुक नहीं हो सका। कृपया पुनः प्रयास करें।', next: 'अब आपकी बारी है!', ahead: 'आपसे पहले {n} मरीज़ · अभी #{m} देखा जा रहा है', loading: 'लोड हो रहा है…' },
};

app.get('/book/:id', (req, res) => {
  const id = String(req.params.id).replace(/[^a-zA-Z0-9-]/g, '');
  res.type('html').send(`<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>Book appointment · CureSync</title>
<style>:root{--p:#6F73D2;--ink:#141A2E;--muted:#5A6485;--line:#E4E7F2;--bg:#F6F7FC}
*{box-sizing:border-box}body{margin:0;font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif;background:var(--bg);color:var(--ink);font-size:17px}
.wrap{max-width:440px;margin:0 auto;padding:22px 18px 40px}
h1{font-size:24px;margin:0 0 2px}.muted{color:var(--muted);font-size:15px}
.langbar{display:flex;gap:8px;margin-bottom:14px}
.lang{width:auto;height:44px;padding:0 16px;border-radius:22px;background:#fff;border:1px solid var(--line);color:var(--ink);font-size:16px;font-weight:600;margin:0}
.lang.active{background:var(--p);color:#fff;border-color:var(--p)}
.card{background:#fff;border:1px solid var(--line);border-radius:16px;padding:20px;margin-top:16px}
label{display:block;font-size:15px;font-weight:600;margin:14px 0 6px}
input{width:100%;height:52px;border:1px solid var(--line);border-radius:12px;padding:0 14px;font-size:17px}
button{width:100%;height:54px;border:0;border-radius:27px;background:var(--p);color:#fff;font-size:17px;font-weight:700;margin-top:18px}
button:disabled{opacity:.5}.big{font-size:48px;font-weight:800;color:var(--p)}.row{display:flex;gap:16px;align-items:baseline}
.ok{background:#E6F6F3;border:1px solid #12A594;border-radius:14px;padding:16px;margin-top:14px;font-size:17px}
.err{color:#F2506E;font-size:15px;margin-top:10px}</style></head>
<body><div class="wrap">
<div class="langbar"><button type="button" class="lang" id="lang_en" onclick="setLang('en')">English</button><button type="button" class="lang" id="lang_te" onclick="setLang('te')">తెలుగు</button><button type="button" class="lang" id="lang_hi" onclick="setLang('hi')">हिंदी</button></div>
<h1 id="h1">Book appointment</h1><p class="muted" id="clinic">Loading…</p><div id="dir" style="margin-top:6px;font-size:15px"></div>
<div id="form" class="card" style="display:none">
  <label id="lblName">Your name</label><input id="name" placeholder="e.g. Ramesh Kumar">
  <label id="lblPhone">Mobile (optional)</label><input id="phone" inputmode="tel" placeholder="98765 43210">
  <button id="btn" onclick="book()">Get my token</button><div id="err" class="err"></div>
</div>
<div id="done" class="card" style="display:none">
  <p class="muted" id="yourToken">Your token</p><div class="row"><span class="big" id="tok"></span></div>
  <div class="ok"><div id="pos"></div></div>
  <p class="muted" id="keepOpen" style="margin-top:14px">Keep this page open — your position updates automatically.</p>
</div>
<p class="muted" id="powered" style="text-align:center;margin-top:24px">Powered by CureSync</p>
</div>
<script>
const ID=${JSON.stringify(id)}, API='/api/v1/clinics/'+ID, STR=${JSON.stringify(BOOK_STR)};
let myTok=null, nowServing=0, clinic=null;
let lang=(function(){try{var l=localStorage.getItem('cs_lang');return STR[l]?l:'en'}catch(e){return 'en'}})();
function t(k){return (STR[lang]&&STR[lang][k])||STR.en[k]||k;}
function el(id){return document.getElementById(id);}
function renderClinic(){el('clinic').textContent=clinic.name+(clinic.open_hours?' · '+clinic.open_hours:'')+(clinic.is_accepting?'':t('notAccepting'));}
function updatePos(){if(myTok==null)return;var ahead=Math.max(0,myTok-nowServing-1);
el('pos').textContent=ahead===0?t('next'):t('ahead').replace('{n}',ahead).replace('{m}',nowServing);}
function applyStatic(){document.title=t('pageTitle');el('h1').textContent=t('title');
el('lblName').textContent=t('name');el('name').placeholder=t('namePh');
el('lblPhone').textContent=t('phone');el('btn').textContent=t('getToken');
el('yourToken').textContent=t('yourToken');el('keepOpen').textContent=t('keepOpen');el('powered').textContent=t('powered');
var d=el('dirLink');if(d)d.textContent=t('directions');
if(clinic)renderClinic();else el('clinic').textContent=t('loading');updatePos();}
function markLang(){['en','te','hi'].forEach(function(c){var b=el('lang_'+c);if(b)b.className='lang'+(c===lang?' active':'');});}
function setLang(l){if(!STR[l])return;lang=l;try{localStorage.setItem('cs_lang',l)}catch(e){};applyStatic();markLang();}
async function load(){try{const r=await fetch(API);const b=await r.json();if(!r.ok)throw 0;clinic=b.clinic;renderClinic();
var ml=b.clinic.maps_link, addr=b.clinic.address;
var href=(ml&&/^https?:\\/\\//i.test(ml))?ml:(addr?'https://www.google.com/maps/search/?api=1&query='+encodeURIComponent(addr):'');
if(href){var dir=el('dir');var a=document.createElement('a');a.id='dirLink';a.href=href;a.target='_blank';a.rel='noopener';a.style.cssText='color:#6F73D2;font-weight:600;text-decoration:none';a.textContent=t('directions');dir.appendChild(a);if(addr){var s=document.createElement('span');s.style.color='#5A6485';s.textContent=' · '+addr;dir.appendChild(s);}}
el('form').style.display=b.clinic.is_accepting?'block':'none';
}catch(e){clinic=null;el('clinic').textContent=t('notFound');}}
async function book(){const name=el('name').value.trim();const phone=el('phone').value.trim();
const err=el('err');if(name.length<2){err.textContent=t('enterName');return;}
el('btn').disabled=true;err.textContent='';
try{const r=await fetch(API+'/book',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({patientName:name,patientPhone:phone})});
const b=await r.json();if(!r.ok)throw new Error(b.error||'failed');myTok=b.token_number;nowServing=b.now_serving;
el('form').style.display='none';el('done').style.display='block';
el('tok').textContent='#'+b.token_number;updatePos();poll();
}catch(e){el('btn').disabled=false;err.textContent=t('bookFail');}}
async function poll(){try{const r=await fetch(API+'/queue');const b=await r.json();nowServing=b.now_serving;updatePos();}catch(e){}setTimeout(poll,20000);}
markLang();applyStatic();load();
</script></body></html>`);
});

const port = process.env.PORT || 8787;
app.listen(port, () => {
  console.log(`CureSync parser on :${port} (model: ${MODEL})`);
  migrate();
});

