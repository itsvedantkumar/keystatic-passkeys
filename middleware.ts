import { Ratelimit } from '@upstash/ratelimit';
import { NextRequest, NextResponse } from 'next/server';
import { SESSION_COOKIE, verifySession } from './lib/auth/session';
import { getIP } from './lib/request';
import { redis } from './lib/redis';
import { timingSafeEqual } from './lib/timing';

// 20 auth attempts per 10 min per IP. Only unauthenticated requests are counted
// (see below) — the Keystatic UI is chatty enough to blow through this bucket
// during normal editing if every request were metered.
//
// Null without Redis: no limiting. See lib/auth/guard.ts for what that costs.
const keystaticlimit = redis
  ? new Ratelimit({
      redis,
      limiter: Ratelimit.slidingWindow(20, '10 m'),
      prefix: 'keystatic:auth',
    })
  : null;

// Rollout/rollback switch. Defaults to 'basic' — plain HTTP Basic Auth against
// the break-glass password — so dropping this code into an existing project
// changes nothing until KEYSTATIC_AUTH_MODE=passkey is set deliberately, once
// passkeys are enrolled and KEYSTATIC_SESSION_SECRET exists.
//
// If the default were 'passkey', the deploy that shipped this file would 503
// /keystatic the moment it landed, before the secret existed in the environment.
// Opt in, never by accident. Rolling back needs no data migration: unset the
// variable and the Basic Auth path is exactly as it was.
const AUTH_MODE = process.env.KEYSTATIC_AUTH_MODE === 'passkey' ? 'passkey' : 'basic';

const LOGIN_PATH = '/auth/keystatic';

// Next's dev-only react-refresh runtime evaluates code with eval(), so without
// this nothing hydrates under `npm run dev` — every client component is inert.
// Never emitted in production builds.
const DEV_EVAL = process.env.NODE_ENV === 'production' ? '' : " 'unsafe-eval'";

function buildCSP(isKeystatic: boolean): string {
  if (isKeystatic) {
    // Keystatic's admin bundle needs inline scripts and styles, and talks to
    // the GitHub API directly when storage is in `github` mode.
    return [
      "default-src 'self'",
      `script-src 'self' 'unsafe-inline'${DEV_EVAL}`,
      "style-src 'self' 'unsafe-inline'",
      "img-src 'self' blob: data: https://avatars.githubusercontent.com",
      "font-src 'self' data:",
      "connect-src 'self' https://api.github.com https://raw.githubusercontent.com",
      "frame-ancestors 'self'",
      "base-uri 'self'",
      "object-src 'none'",
      "form-action 'self'",
    ].join('; ');
  }
  // Everything else, including the passkey login page. Stricter: nothing
  // external, and never framed.
  return [
    "default-src 'self'",
    `script-src 'self' 'unsafe-inline'${DEV_EVAL}`,
    "style-src 'self' 'unsafe-inline'",
    "img-src 'self' blob: data:",
    "font-src 'self' data:",
    "connect-src 'self'",
    "frame-ancestors 'none'",
    "base-uri 'self'",
    "form-action 'self'",
    "object-src 'none'",
  ].join('; ');
}

function allow(): NextResponse {
  const res = NextResponse.next({});
  res.headers.set('Content-Security-Policy', buildCSP(true));
  return res;
}

function deny(status: number, body: string, extra?: HeadersInit): NextResponse {
  const res = new NextResponse(body, { status, headers: extra });
  res.headers.set('Content-Security-Policy', buildCSP(true));
  res.headers.set('Cache-Control', 'no-store');
  return res;
}

/** Basic Auth against the break-glass password. */
function checkBasicAuth(req: NextRequest, password: string): boolean {
  const authHeader = req.headers.get('authorization');
  if (!authHeader?.startsWith('Basic ')) return false;
  try {
    const decoded = atob(authHeader.slice('Basic '.length));
    const colonIndex = decoded.indexOf(':');
    if (colonIndex === -1) return false;
    // Username is ignored — only the password is checked.
    return timingSafeEqual(decoded.slice(colonIndex + 1), password);
  } catch {
    return false;
  }
}

/** True for a top-level page load (as opposed to Keystatic's own fetch calls). */
function isNavigation(req: NextRequest): boolean {
  if (req.headers.get('sec-fetch-mode') === 'navigate') return true;
  return (req.headers.get('accept') ?? '').includes('text/html');
}

export async function middleware(req: NextRequest): Promise<NextResponse> {
  const { pathname, search } = req.nextUrl;
  const isKeystatic =
    pathname.startsWith('/keystatic') || pathname.startsWith('/api/keystatic');

  if (!isKeystatic) {
    // Ungated routes still get a CSP, just a stricter one.
    const res = NextResponse.next({});
    res.headers.set('Content-Security-Policy', buildCSP(false));
    return res;
  }

  const password = process.env.KEYSTATIC_AUTH_PASSWORD;
  const sessionSecret = process.env.KEYSTATIC_SESSION_SECRET;

  // Fail closed. The bug this replaces: with no password configured the
  // middleware fell through to the bottom and left /keystatic wide open — an
  // unset environment variable silently disabled the entire gate. A gate that
  // cannot be enforced must deny, not pass.
  if (!sessionSecret && AUTH_MODE !== 'basic') {
    return deny(503, 'Keystatic auth is not configured');
  }
  if (!password && !redis) {
    // No password AND no credential store: there is no way anyone could ever
    // authenticate, so every request is unauthenticated by definition.
    return deny(503, 'Keystatic auth is not configured');
  }

  // 1. Session cookie — cheap, no network, so it runs before the rate limiter.
  //
  // The limiter sits BEHIND this deliberately. Metering every /keystatic request
  // against 20/10min throttled normal editing, because the admin UI issues a lot
  // of requests. It now meters login attempts only.
  if (AUTH_MODE !== 'basic') {
    const session = await verifySession(
      req.cookies.get(SESSION_COOKIE)?.value,
      sessionSecret
    );
    if (session) return allow();
  }

  // 2. Rate limit unauthenticated traffic only.
  // Skip when IP is 'unknown': bucketing all unknown IPs together would let
  // one bad request globally lock out every user sharing that fallback key.
  if (keystaticlimit) {
    const ip = getIP(req);
    if (ip !== 'unknown') {
      try {
        const { success } = await keystaticlimit.limit(ip);
        if (!success) return deny(429, 'Too Many Requests');
      } catch {
        // Upstash outage: don't fail closed here. Steps 3/4 are the real gate,
        // and denying would lock the admin out for no security gain.
      }
    }
  }

  // 3. Break-glass password over HTTP Basic.
  if (password && checkBasicAuth(req, password)) return allow();

  // 4. Deny.
  if (AUTH_MODE === 'basic') {
    // Default mode: prompt the browser for credentials.
    return deny(401, 'Unauthorized', { 'WWW-Authenticate': 'Basic realm="keystatic"' });
  }

  // No WWW-Authenticate in passkey mode — it would pop the browser's native
  // credential prompt instead of showing the passkey page. `?basic=1` opts back
  // into it: an emergency path that works with JavaScript disabled.
  if (req.nextUrl.searchParams.get('basic') === '1' && password) {
    return deny(401, 'Unauthorized', { 'WWW-Authenticate': 'Basic realm="keystatic"' });
  }

  if (isNavigation(req) && !pathname.startsWith('/api/')) {
    const url = req.nextUrl.clone();
    url.pathname = LOGIN_PATH;
    url.search = `?next=${encodeURIComponent(pathname + search)}`;
    const res = NextResponse.redirect(url, 307);
    res.headers.set('Content-Security-Policy', buildCSP(true));
    res.headers.set('Cache-Control', 'no-store');
    return res;
  }

  return deny(401, JSON.stringify({ error: 'unauthorized' }), {
    'Content-Type': 'application/json',
  });
}

export const config = {
  // Everything except Next.js build output and /.well-known. Excluding by file
  // extension instead would skip any /keystatic/*.png too — dropping auth and
  // CSP on those requests. Match broadly, then decide inside the function.
  matcher: ['/((?!_next/static|_next/image|favicon\\.ico|\\.well-known/).*)'],
};
