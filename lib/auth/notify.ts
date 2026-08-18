/**
 * Out-of-band alerts for anything that changes who can reach /keystatic.
 * Best-effort: never throws, never blocks the caller's result.
 * Node runtime only.
 *
 * Email delivery is OPTIONAL and has no npm dependency — it posts to the Resend
 * REST API with `fetch`. Swapping in Postmark, SES or a Slack webhook means
 * rewriting `deliver()` and nothing else.
 *
 * When email is not configured, alerts go to the process log instead. Be honest
 * with yourself about what that is worth: an alert in a log nobody reads will
 * not tell you that an attacker enrolled a passkey at 3am. The point of these
 * messages is that they arrive somewhere you actually look, out of band from
 * the system being attacked. Logging is the graceful-degradation path so the
 * app runs with zero configuration — it is not the intended production setup.
 */

import { getTrustedIP } from '@/lib/request';

const RESEND_ENDPOINT = 'https://api.resend.com/emails';

type MailConfig = { apiKey: string; to: string; from: string };

/** All three must be present; a half-configured mailer silently drops alerts. */
function mailConfig(): MailConfig | null {
  const apiKey = process.env.RESEND_API_KEY;
  const to = process.env.KEYSTATIC_ALERT_EMAIL;
  const from = process.env.KEYSTATIC_ALERT_FROM;
  if (!apiKey || !to || !from) return null;
  return { apiKey, to, from };
}

async function deliver(cfg: MailConfig, subject: string, text: string): Promise<void> {
  const res = await fetch(RESEND_ENDPOINT, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${cfg.apiKey}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ from: cfg.from, to: cfg.to, subject, text }),
  });
  if (!res.ok) {
    // Read the body for the reason, but never let a parse failure escape.
    const detail = await res.text().catch(() => '');
    console.error(
      `[keystatic-auth] alert email rejected (${res.status}): ${detail.slice(0, 200)}`
    );
  }
}

export async function notifySecurityEvent(subject: string, text: string): Promise<void> {
  const cfg = mailConfig();

  if (!cfg) {
    console.warn(`[keystatic-auth] SECURITY EVENT: ${subject}\n${text}`);
    return;
  }

  // Every failure path swallowed: an alert that cannot be sent must not turn a
  // successful enrollment into a 500.
  try {
    await deliver(cfg, `[keystatic] ${subject}`, text);
  } catch (err: unknown) {
    console.error('[keystatic-auth] alert email failed:', err);
    console.warn(`[keystatic-auth] SECURITY EVENT: ${subject}\n${text}`);
  }
}

/** Context line appended to every alert so an unexpected one is actionable. */
export function requestContext(req: {
  headers: { get(name: string): string | null };
}): string {
  const ip = getTrustedIP(req);
  const ua = req.headers.get('user-agent') ?? 'unknown';
  return `ip: ${ip}\nuser-agent: ${ua}\nat: ${new Date().toISOString()}`;
}
