// Covers lib/auth/enrollment.ts — the policy deciding when the break-glass
// password may enroll a new passkey. Security-critical: once any passkey
// exists, a password-only session must never be enough.
//
// Runs on node:test with --experimental-strip-types, so it imports the
// TypeScript source directly with no build step. Requires Node 22.6+.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { enrollmentBlockedReason, type EnrollmentAuth } from '@/lib/auth/enrollment';

const passkeySession: EnrollmentAuth = {
  via: 'session',
  session: { v: 1, sub: 'admin', m: 'passkey', iat: 0, exp: 0, jti: 'a' },
};
const passwordSession: EnrollmentAuth = {
  via: 'session',
  session: { v: 1, sub: 'admin', m: 'password', iat: 0, exp: 0, jti: 'a' },
};
const tokenAuth: EnrollmentAuth = { via: 'token', session: null };
const passwordAuth: EnrollmentAuth = { via: 'password', session: null };
const noSessionViaSession: EnrollmentAuth = { via: 'session', session: null };

test('zero passkeys enrolled: password bootstrap is allowed', () => {
  assert.equal(enrollmentBlockedReason(passwordAuth, 0), null);
});

test('zero passkeys enrolled: token bootstrap is allowed', () => {
  assert.equal(enrollmentBlockedReason(tokenAuth, 0), null);
});

test('zero passkeys enrolled: even a password-mode session is allowed (bootstrap overrides everything)', () => {
  assert.equal(enrollmentBlockedReason(passwordSession, 0), null);
});

test('zero passkeys enrolled: passkey-mode session is allowed', () => {
  assert.equal(enrollmentBlockedReason(passkeySession, 0), null);
});

test('one or more passkeys: KEYSTATIC_ENROLL_TOKEN bootstrap still allowed', () => {
  assert.equal(enrollmentBlockedReason(tokenAuth, 1), null);
});

test('one or more passkeys: session proved by an existing passkey is allowed', () => {
  assert.equal(enrollmentBlockedReason(passkeySession, 3), null);
});

test('one or more passkeys: password-only session is blocked with a reason string', () => {
  const reason = enrollmentBlockedReason(passwordSession, 1);
  assert.equal(typeof reason, 'string');
  assert.match(reason as string, /passkey/i);
});

test('one or more passkeys: raw "password" auth method (no session) is blocked', () => {
  assert.equal(
    enrollmentBlockedReason(passwordAuth, 1),
    'adding a device requires unlocking with an existing passkey first'
  );
});

test('one or more passkeys: "session" via with a null session is blocked, not a crash', () => {
  assert.equal(
    enrollmentBlockedReason(noSessionViaSession, 2),
    'adding a device requires unlocking with an existing passkey first'
  );
});

test('regression: password-mode session must not slip through once a passkey exists', () => {
  // This is the exact foothold the module's docstring warns about — a leaked
  // password minting a permanent credential. Must stay blocked.
  assert.notEqual(enrollmentBlockedReason(passwordSession, 1), null);
});
