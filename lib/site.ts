/**
 * The one place the deployment's own hostname is configured.
 *
 * Both the WebAuthn relying-party id (lib/webauthn/config.ts) and the Origin
 * allowlist (lib/auth/guard.ts) derive from this, because they have to agree:
 * a passkey registered for rpID `example.com` will not verify against an
 * assertion whose origin is `https://www.example.com`.
 *
 * The default is deliberately a domain you do not own. Forget to set
 * KEYSTATIC_RP_ID in production and every WebAuthn call fails closed with a
 * 403 rather than quietly trusting whatever Host header arrived.
 */
export const PROD_HOST = process.env.KEYSTATIC_RP_ID || 'example.com';

/** Human-readable relying-party name, shown by the OS passkey prompt. */
export const RP_NAME = process.env.KEYSTATIC_RP_NAME || PROD_HOST;

/** Escape a host for safe interpolation into a RegExp. */
export function escapeForRegExp(literal: string): string {
  return literal.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}
