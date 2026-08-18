/**
 * Shared authorisation + CSRF helpers for the /api/auth/* route handlers.
 * Node runtime only.
 */

import { Ratelimit } from '@upstash/ratelimit';
import { NextResponse } from 'next/server';
import { timingSafeEqual } from '@/lib/timing';
import { SESSION_COOKIE, verifySession, type SessionPayload } from '@/lib/auth/session';
import { getIP } from '@/lib/request';
import { redis } from '@/lib/redis';
import { PROD_HOST, escapeForRegExp } from '@/lib/site';

type HeaderBag = { headers: { get(name: string): string | null } };
type CookieBag = { cookies: { get(name: string): { value: string } | undefined } };

export type AdminGranted = {
  ok: true;
  via: 'session' | 'password' | 'token';
  session: SessionPayload | null;
};

export type AdminAuth = AdminGranted | { ok: false; status: number; error: string };

export { enrollmentBlockedReason } from '@/lib/auth/enrollment';

export function sessionSecret(): string | undefined {
  return process.env.KEYSTATIC_SESSION_SECRET;
}

// One shared bucket for every path that compares a caller-supplied secret
// against KEYSTATIC_AUTH_PASSWORD or KEYSTATIC_ENROLL_TOKEN. It lives here
// rather than per-route so no endpoint can accidentally become an unthrottled
// brute-force oracle for the break-glass password.
//
// Null when Redis is not configured — see limitSecretAttempt for what that
// costs you.
const secretLimit = redis
  ? new Ratelimit({
      redis,
      limiter: Ratelimit.slidingWindow(5, '15 m'),
      prefix: 'keystatic:pw',
    })
  : null;

/**
 * False when the caller has exhausted their password/token attempt budget.
 *
 * With no Redis configured this returns true unconditionally: there is no
 * limiting at all. That is a real reduction in security — the break-glass
 * password becomes online-brute-forceable at whatever rate your host allows —
 * and it is why KEYSTATIC_AUTH_PASSWORD must be long and random rather than
 * memorable. Configure Upstash before exposing this to the internet.
 */
export async function limitSecretAttempt(req: HeaderBag): Promise<boolean> {
  if (!secretLimit) return true;
  const ip = getIP(req);
  // Skip 'unknown' per the convention elsewhere: one shared bucket would let a
  // single bad request lock out everyone behind that fallback key.
  if (ip === 'unknown') return true;
  const { success } = await secretLimit.limit(ip);
  return success;
}

export function jsonError(status: number, error: string): NextResponse {
  return NextResponse.json({ error }, { status });
}

// Built once. `PROD_HOST` is escaped because it comes from an env var, and an
// unescaped dot in a hostname would make the regex match far more than intended
// (`example.com` would also match `exampleXcom`).
const PROD_ORIGIN = new RegExp(`^https://([a-z0-9-]+\\.)*${escapeForRegExp(PROD_HOST)}$`);
const DEV_ORIGIN = new RegExp(
  `^(https://${escapeForRegExp(PROD_HOST)}|https?://localhost(:\\d+)?|https?://127\\.0\\.0\\.1(:\\d+)?)$`
);

/**
 * Origin allowlist. A missing Origin header is rejected, not waved through —
 * that is the whole point, since a cross-site form POST cannot set one.
 */
export function checkOrigin(req: HeaderBag): boolean {
  const origin = req.headers.get('origin') ?? '';
  if (process.env.NODE_ENV === 'production') {
    if (PROD_ORIGIN.test(origin)) return true;
    // Preview deploys only. Accepting any *.vercel.app in production would
    // admit an attacker-hosted page on that shared domain.
    return (
      process.env.VERCEL_ENV === 'preview' &&
      /^https:\/\/[a-z0-9-]+\.vercel\.app$/.test(origin)
    );
  }
  return DEV_ORIGIN.test(origin);
}

/** Forces a CORS preflight, which blocks cross-site HTML-form POSTs. */
export function checkContentType(req: HeaderBag): boolean {
  return (req.headers.get('content-type') ?? '').includes('application/json');
}

function passwordFromBasicHeader(req: HeaderBag): string | null {
  const header = req.headers.get('authorization');
  if (!header?.startsWith('Basic ')) return null;
  try {
    const decoded = atob(header.slice('Basic '.length));
    const colon = decoded.indexOf(':');
    return colon === -1 ? null : decoded.slice(colon + 1);
  } catch {
    return null;
  }
}

/**
 * Accepts, in order: a valid session cookie, the break-glass password (Basic
 * header or `password` in the JSON body), or the bootstrap enroll token.
 * Denies by default — including when KEYSTATIC_SESSION_SECRET is missing, since
 * no session could be minted or verified anyway.
 */
export async function requireAdmin(
  req: HeaderBag & CookieBag,
  body?: { password?: unknown }
): Promise<AdminAuth> {
  const secret = sessionSecret();
  if (!secret) {
    return { ok: false, status: 503, error: 'auth misconfigured' };
  }

  const session = await verifySession(req.cookies.get(SESSION_COOKIE)?.value, secret);
  if (session) return { ok: true, via: 'session', session };

  const bodyPassword = typeof body?.password === 'string' ? body.password : null;
  const headerPassword = passwordFromBasicHeader(req);
  const headerToken = req.headers.get('x-enroll-token');

  // Meter before any comparison, and only when a secret was actually offered —
  // session-cookie traffic must not consume the budget.
  if (bodyPassword || headerPassword || headerToken) {
    if (!(await limitSecretAttempt(req))) {
      return { ok: false, status: 429, error: 'too many attempts' };
    }
  }

  const configured = process.env.KEYSTATIC_AUTH_PASSWORD;
  if (configured) {
    const provided = headerPassword ?? bodyPassword;
    if (provided && timingSafeEqual(provided, configured)) {
      return { ok: true, via: 'password', session: null };
    }
  }

  const enrollToken = process.env.KEYSTATIC_ENROLL_TOKEN;
  if (enrollToken && headerToken && timingSafeEqual(headerToken, enrollToken)) {
    return { ok: true, via: 'token', session: null };
  }

  return { ok: false, status: 401, error: 'unauthorized' };
}
