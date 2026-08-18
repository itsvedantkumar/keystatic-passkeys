/**
 * Upstash Redis client, or null when it is not configured.
 *
 * OPTIONAL. Everything that touches this module handles `null`:
 *   - rate limiters degrade to "no limiting" (see lib/auth/guard.ts)
 *   - the credential store throws RedisUnavailableError, which the WebAuthn
 *     routes translate into a 503 (see lib/webauthn/store.ts)
 *
 * So the app boots and the break-glass password still works with no Redis at
 * all — you just cannot enroll or use passkeys, because there is nowhere to put
 * the credentials. That is the intended degradation, not a bug.
 *
 * Half-configured is treated as an error rather than silently falling back to
 * null: a deploy that meant to have Redis and typo'd one of the two variables
 * would otherwise come up with rate limiting quietly disabled.
 */
import { Redis } from '@upstash/redis';

const upstashUrl = process.env.UPSTASH_REDIS_REST_URL;
const upstashToken = process.env.UPSTASH_REDIS_REST_TOKEN;

if ((upstashUrl && !upstashToken) || (!upstashUrl && upstashToken)) {
  throw new Error(
    'Upstash misconfigured: set both UPSTASH_REDIS_REST_URL and UPSTASH_REDIS_REST_TOKEN or neither'
  );
}

export const redis = upstashUrl && upstashToken ? Redis.fromEnv() : null;
