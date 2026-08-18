/**
 * Relying-party identity + capability checks for the /keystatic passkey gate.
 * Node runtime only (imported by app/api/auth/**).
 */

import { redis } from '@/lib/redis';
import { PROD_HOST, RP_NAME } from '@/lib/site';

/**
 * Single admin, forever — so every passkey shares one user handle and the OS
 * groups them under a single entry. Changing this orphans existing passkeys in
 * the OS UI (they still verify; lookup is by credential id, not user handle).
 *
 * This system has no user table and no notion of "who": reaching /keystatic at
 * all means you are the admin. If you need multiple distinct admins, the user
 * handle has to become per-user and lib/webauthn/store.ts needs an owner column.
 */
export const WEBAUTHN_USER_ID = new TextEncoder().encode('keystatic-admin');
export const WEBAUTHN_USER_NAME = process.env.KEYSTATIC_ADMIN_LABEL || 'admin';
export const WEBAUTHN_USER_DISPLAY_NAME =
  process.env.KEYSTATIC_ADMIN_LABEL || 'Keystatic Admin';

export type RelyingParty = {
  rpID: string;
  rpName: string;
  origins: string[];
};

/**
 * rpID and expected origins are pinned per environment — never derived from the
 * Host header in production, which an attacker controls on some edge configs.
 * Origin comparison in @simplewebauthn is a literal string match, so entries
 * must be exact and unslashed.
 */
export function getRelyingParty(req: {
  headers: { get(name: string): string | null };
}): RelyingParty {
  const rpName = RP_NAME;

  if (process.env.VERCEL_ENV === 'production') {
    return { rpID: PROD_HOST, rpName, origins: [`https://${PROD_HOST}`] };
  }

  if (process.env.VERCEL_ENV === 'preview') {
    const host = req.headers.get('x-forwarded-host') ?? process.env.VERCEL_URL ?? '';
    // Only trust the forwarded host on preview, and only for vercel.app domains.
    if (host.endsWith('.vercel.app')) {
      return { rpID: host, rpName, origins: [`https://${host}`] };
    }
    return { rpID: PROD_HOST, rpName, origins: [`https://${PROD_HOST}`] };
  }

  return {
    rpID: 'localhost',
    rpName,
    origins: ['http://localhost:3000', 'http://localhost:3001'],
  };
}

export function isPasswordConfigured(): boolean {
  return Boolean(process.env.KEYSTATIC_AUTH_PASSWORD);
}

/** Passkeys need Redis for credential + challenge storage. */
export function isPasskeysAvailable(): boolean {
  return redis !== null;
}
