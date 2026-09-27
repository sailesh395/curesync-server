// Server-side OTP: generate, hash, expire, attempt-cap. The store is injected (a Map) so this
// is pure and unit-testable without booting Express or a real clock.
// ponytail: in-memory Map — fine for Render's single free instance + 5-min OTPs; it resets on
// restart and won't share across instances. Upgrade to Redis/DB when you scale past one instance.
import crypto from 'node:crypto';

export const OTP_TTL_MS = 5 * 60 * 1000; // code valid 5 minutes
export const RESEND_MS = 30 * 1000; // one code per phone per 30s
export const MAX_ATTEMPTS = 5; // wrong tries before the code is burned

const sha = (c) => crypto.createHash('sha256').update(String(c)).digest('hex');

/** 4-digit code, zero-padded. Matches the app's OTP_LENGTH. */
export function genCode() {
  return String(crypto.randomInt(0, 10000)).padStart(4, '0');
}

/** Create/refresh a code for `phone`. Rate-limited. Returns the plaintext code to send (never store it). */
export function requestOtp(store, phone, now = Date.now()) {
  const prev = store.get(phone);
  if (prev && now - prev.sentAt < RESEND_MS) {
    return { ok: false, error: 'too_soon', retryIn: Math.ceil((RESEND_MS - (now - prev.sentAt)) / 1000) };
  }
  const code = genCode();
  store.set(phone, { hash: sha(code), expiresAt: now + OTP_TTL_MS, attempts: 0, sentAt: now });
  return { ok: true, code, expiresIn: OTP_TTL_MS / 1000 };
}

/** Verify a submitted code. Burns the code on success, expiry, or too many attempts. */
export function verifyOtp(store, phone, code, now = Date.now()) {
  const e = store.get(phone);
  if (!e) return { ok: false, error: 'no_otp' };
  if (now > e.expiresAt) { store.delete(phone); return { ok: false, error: 'expired' }; }
  if (e.attempts >= MAX_ATTEMPTS) { store.delete(phone); return { ok: false, error: 'too_many' }; }
  if (sha(String(code).trim()) !== e.hash) { e.attempts += 1; return { ok: false, error: 'bad_code' }; }
  store.delete(phone);
  return { ok: true };
}
