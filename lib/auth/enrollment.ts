import type { SessionPayload } from '@/lib/auth/session';

export type EnrollmentAuth = {
  via: 'session' | 'password' | 'token';
  session: SessionPayload | null;
};

/**
 * Who may add a new passkey. Pure policy, no I/O — kept in its own module so it
 * stays directly testable.
 *
 * The break-glass password is deliberately NOT enough once a passkey exists.
 * Otherwise a leaked or guessed password would let someone mint their own
 * permanent credential — a foothold that survives rotating the password. So:
 *
 *   - zero passkeys enrolled  → password/token bootstrap is allowed
 *   - one or more enrolled    → only a session that was itself proved by a
 *                               passkey, or KEYSTATIC_ENROLL_TOKEN
 *
 * Losing every device is therefore recovered by setting KEYSTATIC_ENROLL_TOKEN
 * in the deployment environment — something only the account owner can do.
 */
export function enrollmentBlockedReason(
  auth: EnrollmentAuth,
  existingCredentials: number
): string | null {
  if (existingCredentials === 0) return null;
  if (auth.via === 'token') return null;
  if (auth.via === 'session' && auth.session?.m === 'passkey') return null;
  return 'adding a device requires unlocking with an existing passkey first';
}
