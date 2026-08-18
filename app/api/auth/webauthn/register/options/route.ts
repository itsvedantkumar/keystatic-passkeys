import { generateRegistrationOptions } from '@simplewebauthn/server';
import { Ratelimit } from '@upstash/ratelimit';
import { NextRequest, NextResponse } from 'next/server';
import {
  checkContentType,
  checkOrigin,
  enrollmentBlockedReason,
  jsonError,
  requireAdmin,
  sessionSecret,
} from '@/lib/auth/guard';
import {
  CHALLENGE_TTL_SEC,
  SESSION_TTL_SEC,
  challengeCookie,
  sessionCookie,
  signSession,
} from '@/lib/auth/session';
import {
  WEBAUTHN_USER_DISPLAY_NAME,
  WEBAUTHN_USER_ID,
  WEBAUTHN_USER_NAME,
  getRelyingParty,
} from '@/lib/webauthn/config';
import {
  isRedisUnavailable,
  listCredentials,
  newNonce,
  putChallenge,
} from '@/lib/webauthn/store';
import { getIP } from '@/lib/request';
import { redis } from '@/lib/redis';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

const ratelimit = redis
  ? new Ratelimit({
      redis,
      limiter: Ratelimit.slidingWindow(5, '1 h'),
      prefix: 'keystatic:enroll',
    })
  : null;

export async function POST(req: NextRequest): Promise<NextResponse> {
  if (!checkOrigin(req)) return jsonError(403, 'bad origin');
  if (!checkContentType(req)) return jsonError(415, 'expected application/json');

  const secret = sessionSecret();
  if (!secret) return jsonError(503, 'auth misconfigured');

  if (ratelimit) {
    const ip = getIP(req);
    if (ip !== 'unknown') {
      const { success } = await ratelimit.limit(ip);
      if (!success) return jsonError(429, 'too many attempts');
    }
  }

  let body: { password?: unknown } = {};
  try {
    body = (await req.json()) as { password?: unknown };
  } catch {
    // An empty body is fine when authorising via the session cookie.
  }

  const auth = await requireAdmin(req, body);
  if (!auth.ok) return jsonError(auth.status, auth.error);

  try {
    const existing = await listCredentials();

    const blocked = enrollmentBlockedReason(auth, existing.length);
    if (blocked) return jsonError(403, blocked);

    const { rpID, rpName } = getRelyingParty(req);

    const options = await generateRegistrationOptions({
      rpName,
      rpID,
      userID: WEBAUTHN_USER_ID,
      userName: WEBAUTHN_USER_NAME,
      userDisplayName: WEBAUTHN_USER_DISPLAY_NAME,
      // Attestation adds no value for a single self-hosted admin and leaks
      // device model information.
      attestationType: 'none',
      // Blocks re-registering an authenticator already enrolled — the browser
      // throws InvalidStateError, which the UI translates.
      excludeCredentials: existing.map((c) => ({
        id: c.id,
        transports: c.transports,
      })),
      authenticatorSelection: {
        // Discoverable, so login needs no username typed.
        residentKey: 'required',
        // Forces Touch ID / Face ID / PIN rather than mere presence.
        userVerification: 'required',
        // authenticatorAttachment deliberately unset so USB security keys work.
      },
    });

    const nonce = newNonce();
    await putChallenge(nonce, {
      kind: 'reg',
      challenge: options.challenge,
      ip: getIP(req),
    });

    const headers: [string, string][] = [
      ['Set-Cookie', challengeCookie(nonce, CHALLENGE_TTL_SEC)],
      ['Cache-Control', 'no-store'],
    ];

    // Bootstrapping via password/token also mints a session, so the password is
    // typed once and several devices can be enrolled back to back.
    if (auth.via !== 'session') {
      const token = await signSession({ m: 'password' }, secret);
      headers.push(['Set-Cookie', sessionCookie(token, SESSION_TTL_SEC)]);
    }

    return NextResponse.json(options, { headers });
  } catch (err) {
    if (isRedisUnavailable(err)) return jsonError(503, 'passkeys unavailable');
    return jsonError(503, 'enrollment unavailable');
  }
}
