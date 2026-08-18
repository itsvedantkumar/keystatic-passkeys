import { NextRequest, NextResponse } from 'next/server';
import { SESSION_COOKIE, verifySession } from '@/lib/auth/session';
import { sessionSecret } from '@/lib/auth/guard';
import { isPasskeysAvailable, isPasswordConfigured } from '@/lib/webauthn/config';
import { countCredentials } from '@/lib/webauthn/store';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

/**
 * Capability probe so the login UI renders the right affordances. Returns
 * booleans and a count only — never credential ids.
 */
export async function GET(req: NextRequest): Promise<NextResponse> {
  const secret = sessionSecret();
  const session = await verifySession(req.cookies.get(SESSION_COOKIE)?.value, secret);

  const passkeysAvailable = isPasskeysAvailable();
  let enrolledCount = 0;
  if (passkeysAvailable) {
    try {
      enrolledCount = await countCredentials();
    } catch {
      enrolledCount = 0;
    }
  }

  return NextResponse.json(
    {
      configured: Boolean(secret),
      passkeysAvailable,
      passwordEnabled: isPasswordConfigured(),
      enrolledCount,
      sessionActive: session !== null,
      sessionMethod: session?.m ?? null,
      // Mirrors enrollmentBlockedReason() in lib/auth/enrollment.ts — the server
      // enforces it; this only drives the UI.
      canEnroll: enrolledCount === 0 || session?.m === 'passkey',
    },
    { headers: { 'Cache-Control': 'no-store' } }
  );
}
