/**
 * Stateless admin session cookie for the /keystatic gate.
 *
 * Edge-safe by construction: this module must import NOTHING but Web Crypto,
 * TextEncoder and atob/btoa. It is shared with middleware.ts, which runs on the
 * Edge runtime — pulling in Redis, Node builtins or @simplewebauthn here would
 * break the middleware bundle.
 *
 * Format:  <b64url(payload JSON)>.<b64url(HMAC-SHA256 of part 0)>
 *
 * Sessions are signed, not stored. Revocation = rotate KEYSTATIC_SESSION_SECRET,
 * which invalidates every outstanding session on the next request.
 */

export const SESSION_COOKIE = 'ks_session';
export const CHALLENGE_COOKIE = 'ks_chal';
export const SESSION_TTL_SEC = 12 * 60 * 60; // 12h
export const CHALLENGE_TTL_SEC = 300; // 5m

// Guard against pathological input before doing any crypto work.
const MAX_COOKIE_LEN = 512;

export type SessionPayload = {
  v: 1;
  sub: 'admin';
  m: 'passkey' | 'password';
  /** First 16 chars of the credential id that minted this session (passkey only). */
  cid?: string;
  iat: number;
  exp: number;
  jti: string;
};

export function bytesToB64Url(bytes: Uint8Array): string {
  let bin = '';
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export function b64UrlToBytes(s: string): Uint8Array<ArrayBuffer> {
  const pad = s.length % 4 === 0 ? '' : '='.repeat(4 - (s.length % 4));
  const bin = atob(s.replace(/-/g, '+').replace(/_/g, '/') + pad);
  const out = new Uint8Array(new ArrayBuffer(bin.length));
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

async function hmacKey(secret: string, usage: KeyUsage[]): Promise<CryptoKey> {
  return crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    usage
  );
}

export async function signSession(
  claims: Pick<SessionPayload, 'm'> & Partial<Pick<SessionPayload, 'cid'>>,
  secret: string,
  ttlSec: number = SESSION_TTL_SEC
): Promise<string> {
  const now = Math.floor(Date.now() / 1000);
  const jtiBytes = new Uint8Array(8);
  crypto.getRandomValues(jtiBytes);
  const payload: SessionPayload = {
    v: 1,
    sub: 'admin',
    m: claims.m,
    ...(claims.cid ? { cid: claims.cid.slice(0, 16) } : {}),
    iat: now,
    exp: now + ttlSec,
    jti: bytesToB64Url(jtiBytes),
  };
  const body = bytesToB64Url(new TextEncoder().encode(JSON.stringify(payload)));
  const key = await hmacKey(secret, ['sign']);
  const sig = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(body));
  return `${body}.${bytesToB64Url(new Uint8Array(sig))}`;
}

/**
 * Returns the payload when the cookie is well-formed, correctly signed and
 * unexpired. Returns null on ANY problem — never throws. An exception thrown
 * inside Edge middleware fails the request in ways that are hard to reason about.
 */
export async function verifySession(
  cookie: string | undefined,
  secret: string | undefined
): Promise<SessionPayload | null> {
  if (!cookie || !secret) return null;
  if (cookie.length > MAX_COOKIE_LEN) return null;
  try {
    const parts = cookie.split('.');
    if (parts.length !== 2) return null;
    const [body, sig] = parts;
    if (!body || !sig) return null;

    const key = await hmacKey(secret, ['verify']);
    // crypto.subtle.verify is constant-time.
    const ok = await crypto.subtle.verify(
      'HMAC',
      key,
      b64UrlToBytes(sig),
      new TextEncoder().encode(body)
    );
    if (!ok) return null;

    const payload = JSON.parse(
      new TextDecoder().decode(b64UrlToBytes(body))
    ) as SessionPayload;

    if (payload.v !== 1) return null;
    if (payload.sub !== 'admin') return null;
    if (payload.m !== 'passkey' && payload.m !== 'password') return null;
    if (typeof payload.exp !== 'number') return null;
    if (payload.exp <= Math.floor(Date.now() / 1000)) return null;

    return payload;
  } catch {
    return null;
  }
}

/**
 * Set-Cookie value for the session. `Secure` is omitted outside production so
 * http://localhost works; `SameSite=Lax` is load-bearing — Keystatic's GitHub
 * OAuth callback arrives as a top-level cross-site GET and `Strict` would drop
 * the cookie on that hop.
 */
export function sessionCookie(value: string, maxAge: number): string {
  const attrs = [
    `${SESSION_COOKIE}=${value}`,
    'HttpOnly',
    'SameSite=Lax',
    'Path=/',
    `Max-Age=${maxAge}`,
  ];
  if (process.env.NODE_ENV === 'production') attrs.push('Secure');
  return attrs.join('; ');
}

export function clearSessionCookie(): string {
  return sessionCookie('', 0);
}

export function challengeCookie(value: string, maxAge: number): string {
  const attrs = [
    `${CHALLENGE_COOKIE}=${value}`,
    'HttpOnly',
    'SameSite=Lax',
    'Path=/',
    `Max-Age=${maxAge}`,
  ];
  if (process.env.NODE_ENV === 'production') attrs.push('Secure');
  return attrs.join('; ');
}

export function clearChallengeCookie(): string {
  return challengeCookie('', 0);
}
