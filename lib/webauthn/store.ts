/**
 * Redis persistence for WebAuthn credentials and in-flight challenges.
 * Owns every `ks:*` key string — nothing else in the codebase should build one.
 * Node runtime only.
 *
 * Every function here throws RedisUnavailableError when Redis is not
 * configured. Callers translate that into a 503 via isRedisUnavailable() rather
 * than pretending there are zero credentials — "no passkeys enrolled" and "the
 * credential database is unreachable" must not look the same to the gate.
 */

import type { AuthenticatorTransportFuture } from '@simplewebauthn/server';
import { redis } from '@/lib/redis';
import { CHALLENGE_TTL_SEC } from '@/lib/auth/session';

const CREDS_SET = 'ks:wa:creds';
const credKey = (id: string) => `ks:wa:cred:${id}`;
const chalKey = (nonce: string) => `ks:wa:chal:${nonce}`;

export type StoredCredential = {
  /** base64url credential id */
  id: string;
  /**
   * base64url of the COSE public key. MUST be a string: Upstash serialises to
   * JSON, and a raw Uint8Array round-trips as {"0":4,"1":167,…} — silently
   * corrupting the key and failing every subsequent assertion.
   *
   * This fails late and quietly. Enrollment succeeds, the credential looks fine
   * in the manage UI, and only the NEXT authentication attempt breaks — with a
   * signature error that points nowhere near the real cause. Anything binary
   * you put into Upstash needs the same base64url treatment.
   */
  publicKey: string;
  counter: number;
  transports?: AuthenticatorTransportFuture[];
  deviceType: string;
  backedUp: boolean;
  label: string;
  createdAt: number;
  lastUsedAt: number | null;
  /** Set when the signature counter regressed — a possible cloned authenticator. */
  suspended?: boolean;
};

export type ChallengeRecord = {
  kind: 'reg' | 'auth';
  challenge: string;
  ip: string;
};

class RedisUnavailableError extends Error {
  constructor() {
    super('Upstash Redis is not configured — passkeys are unavailable');
    this.name = 'RedisUnavailableError';
  }
}

function db() {
  if (!redis) throw new RedisUnavailableError();
  return redis;
}

export function isRedisUnavailable(err: unknown): boolean {
  return err instanceof RedisUnavailableError;
}

async function listCredentialIds(): Promise<string[]> {
  return db().smembers(CREDS_SET);
}

export async function countCredentials(): Promise<number> {
  return db().scard(CREDS_SET);
}

export async function getCredential(id: string): Promise<StoredCredential | null> {
  return db().get<StoredCredential>(credKey(id));
}

export async function listCredentials(): Promise<StoredCredential[]> {
  const ids = await listCredentialIds();
  if (ids.length === 0) return [];
  const records = await Promise.all(ids.map((id) => getCredential(id)));
  return records.filter((c): c is StoredCredential => c !== null);
}

export async function saveCredential(cred: StoredCredential): Promise<void> {
  const client = db();
  await client.set(credKey(cred.id), cred);
  await client.sadd(CREDS_SET, cred.id);
}

export async function updateCredential(
  id: string,
  patch: Partial<StoredCredential>
): Promise<void> {
  const existing = await getCredential(id);
  if (!existing) return;
  await db().set(credKey(id), { ...existing, ...patch });
}

export async function deleteCredential(id: string): Promise<void> {
  const client = db();
  await client.del(credKey(id));
  await client.srem(CREDS_SET, id);
}

/**
 * Atomically remove an id from the index, returning 1 if it was present.
 * Callers that need a "never delete the last credential" guard must remove
 * first and re-add on regret — a read-then-delete check races with a concurrent
 * delete of a different credential and can empty the set.
 */
export async function unlinkCredentialId(id: string): Promise<number> {
  return db().srem(CREDS_SET, id);
}

export async function relinkCredentialId(id: string): Promise<void> {
  await db().sadd(CREDS_SET, id);
}

export async function deleteCredentialRecord(id: string): Promise<void> {
  await db().del(credKey(id));
}

export async function putChallenge(
  nonce: string,
  record: ChallengeRecord
): Promise<void> {
  await db().set(chalKey(nonce), record, { ex: CHALLENGE_TTL_SEC });
}

/**
 * Atomic read-and-delete. Single-use by construction, so a replayed assertion
 * finds no challenge. A non-atomic get-then-del would race.
 */
export async function burnChallenge(nonce: string): Promise<ChallengeRecord | null> {
  return db().getdel<ChallengeRecord>(chalKey(nonce));
}

export function newNonce(): string {
  return crypto.randomUUID().replace(/-/g, '');
}
