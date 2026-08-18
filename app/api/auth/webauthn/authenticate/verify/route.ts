import {
  verifyAuthenticationResponse,
  type AuthenticationResponseJSON,
} from '@simplewebauthn/server';
import { NextRequest, NextResponse } from 'next/server';
import {
  checkContentType,
  checkOrigin,
  jsonError,
  sessionSecret,
} from '@/lib/auth/guard';
import {
  CHALLENGE_COOKIE,
  SESSION_TTL_SEC,
  b64UrlToBytes,
  clearChallengeCookie,
  sessionCookie,
  signSession,
} from '@/lib/auth/session';
import { getRelyingParty } from '@/lib/webauthn/config';
import {
  burnChallenge,
  getCredential,
  isRedisUnavailable,
  updateCredential,
} from '@/lib/webauthn/store';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

// Never echo the library's exception text: it distinguishes "no such credential"
// from "bad signature", which is an enumeration oracle.
const GENERIC = 'authentication failed';

export async function POST(req: NextRequest): Promise<NextResponse> {
  if (!checkOrigin(req)) return jsonError(403, 'bad origin');
  if (!checkContentType(req)) return jsonError(415, 'expected application/json');

  const secret = sessionSecret();
  if (!secret) return jsonError(503, 'auth misconfigured');

  const nonce = req.cookies.get(CHALLENGE_COOKIE)?.value;
  if (!nonce) return jsonError(400, GENERIC);

  let response: AuthenticationResponseJSON;
  try {
    response = (await req.json()) as AuthenticationResponseJSON;
  } catch {
    return jsonError(400, 'invalid body');
  }
  if (!response?.id) return jsonError(400, GENERIC);

  const failed = (status: number, error = GENERIC) =>
    NextResponse.json(
      { error },
      { status, headers: { 'Set-Cookie': clearChallengeCookie() } }
    );

  try {
    // Atomic read+delete — a replayed assertion finds no challenge.
    const challenge = await burnChallenge(nonce);
    if (!challenge || challenge.kind !== 'auth') return failed(400);

    const cred = await getCredential(response.id);
    if (!cred || cred.suspended) return failed(401);

    const { rpID, origins } = getRelyingParty(req);

    let verification;
    try {
      verification = await verifyAuthenticationResponse({
        response,
        expectedChallenge: challenge.challenge,
        expectedOrigin: origins,
        expectedRPID: rpID,
        requireUserVerification: true,
        credential: {
          id: cred.id,
          publicKey: b64UrlToBytes(cred.publicKey),
          // Deliberately 0, not cred.counter: that disables the library's own
          // counter check (@simplewebauthn/server v13 throws
          // `Response counter value N was lower than expected M` *before* it
          // verifies the signature, so an unsigned forged assertion could trip
          // it). We redo the comparison below, after the signature is proven.
          counter: 0,
          transports: cred.transports,
        },
      });
    } catch {
      // Any verification failure is just a 401. Suspension is never inferred
      // from the library's exception text: the wording is not API surface, so
      // a reworded upstream message would silently disable clone detection and
      // an unrelated error mentioning "counter" would brick a real hardware key.
      return failed(401);
    }

    if (!verification.verified) return failed(401);

    // Clone detection, on verified data only. Per WebAuthn §6.1.1, a signature
    // counter that fails to advance means the same credential is in use from
    // two places — disable it rather than merely refusing this attempt.
    // Caveat: synced passkeys (iCloud Keychain, Google Password Manager) always
    // report signCount 0; zero on both sides is spec-legal and must NOT suspend,
    // so this only ever fires for hardware keys that do maintain a counter.
    const newCounter = verification.authenticationInfo.newCounter;
    if ((newCounter > 0 || cred.counter > 0) && newCounter <= cred.counter) {
      await updateCredential(cred.id, { suspended: true });
      return failed(403, 'credential suspended');
    }

    await updateCredential(cred.id, {
      counter: verification.authenticationInfo.newCounter,
      lastUsedAt: Date.now(),
      backedUp: verification.authenticationInfo.credentialBackedUp,
      deviceType: verification.authenticationInfo.credentialDeviceType,
    });

    const token = await signSession({ m: 'passkey', cid: cred.id }, secret);
    return NextResponse.json(
      { ok: true },
      {
        headers: [
          ['Set-Cookie', sessionCookie(token, SESSION_TTL_SEC)],
          ['Set-Cookie', clearChallengeCookie()],
          ['Cache-Control', 'no-store'],
        ],
      }
    );
  } catch (err) {
    if (isRedisUnavailable(err)) return jsonError(503, 'passkeys unavailable');
    return jsonError(503, 'authentication unavailable');
  }
}
