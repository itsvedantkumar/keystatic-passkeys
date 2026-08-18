/**
 * Constant-time string comparison using XOR over padded UTF-8 bytes.
 * Safe in both Node.js and Edge runtimes (uses only TextEncoder + Uint8Array).
 *
 * `node:crypto`'s timingSafeEqual would work in the route handlers but not in
 * middleware.ts, which runs on the Edge runtime — hence the hand-rolled version.
 */
export function timingSafeEqual(a: string, b: string): boolean {
  const enc = new TextEncoder();
  const aBytes = enc.encode(a);
  const bBytes = enc.encode(b);
  const maxLen = Math.max(aBytes.length, bBytes.length);
  const aPadded = new Uint8Array(maxLen);
  const bPadded = new Uint8Array(maxLen);
  aPadded.set(aBytes);
  bPadded.set(bBytes);
  let diff = aBytes.length ^ bBytes.length;
  for (let i = 0; i < maxLen; i++) diff |= aPadded[i] ^ bPadded[i];
  return diff === 0;
}
