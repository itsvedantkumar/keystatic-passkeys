/**
 * Only ever redirect back into the Keystatic admin — an unvalidated `?next=`
 * would be an open redirect.
 */
export function safeNext(raw: string | null | undefined): string {
  const fallback = '/keystatic';
  if (!raw) return fallback;
  if (!raw.startsWith('/keystatic')) return fallback;
  if (raw.startsWith('//') || raw.includes('\\')) return fallback;
  return raw;
}
