/**
 * Client IP for rate limiting and audit lines.
 *
 * `x-vercel-forwarded-for` is set by the platform and cannot be spoofed by the
 * client, so it always wins. The remaining headers are best-effort ONLY: with no
 * trusted proxy stripping them, any client can send `x-forwarded-for: 1.2.3.4`
 * and rotate it per request to defeat a limiter. We still read them because
 * every caller skips rate limiting when this returns 'unknown', so without a
 * fallback a self-hosted or proxied deploy has no limiter at all — spoofable
 * limiting beats none. Never treat a fallback value as an identity.
 *
 * Deploying somewhere other than Vercel: replace `x-vercel-forwarded-for` with
 * whichever header YOUR platform sets and guarantees to overwrite
 * (`cf-connecting-ip` on Cloudflare, `fly-client-ip` on Fly.io, and so on). The
 * distinction that matters is "the edge overwrites this" vs "the client can
 * send it" — not the header name.
 */
export function getIP(req: { headers: { get(name: string): string | null } }): string {
  const vercel = req.headers.get('x-vercel-forwarded-for')?.trim();
  if (vercel) return vercel;

  // Comma-separated proxy chain; the first entry is the client, the rest are hops.
  const forwarded = req.headers.get('x-forwarded-for')?.split(',')[0]?.trim();
  if (forwarded) return forwarded;

  return req.headers.get('x-real-ip')?.trim() || 'unknown';
}

/**
 * Platform-verified IP for security decisions (alerts, identity).
 *
 * Only uses `x-vercel-forwarded-for`, set by the platform and not spoofable by clients.
 * Falls back to 'unknown' if the header is missing. Never uses the spoofable fallbacks that
 * `getIP` provides for rate limiting, since a fallback value must never be treated as an identity.
 *
 * Use `getTrustedIP` for security alerts and identity claims.
 * Use `getIP` for rate limiting and audit logging.
 */
export function getTrustedIP(req: {
  headers: { get(name: string): string | null };
}): string {
  return req.headers.get('x-vercel-forwarded-for')?.trim() || 'unknown';
}
