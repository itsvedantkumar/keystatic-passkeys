# keystatic-passkeys

Gating the [Keystatic](https://keystatic.com) CMS admin route with WebAuthn passkeys —
Touch ID, Face ID, Windows Hello, or a hardware key — with a break-glass password as the
recovery path of last resort.

Keystatic ships GitHub OAuth for its own storage layer, but nothing that answers "who is
allowed to open `/keystatic` in the first place". On a personal or small-team site that
route is effectively **git write access to the content repo**, and the usual answer is an
HTTP Basic Auth password in middleware. This repo replaces that with passkeys.

> **This is a reference implementation, not a supported library.** There is no npm package,
> no semver, no compatibility promise, and no security guarantee. It is extracted from one
> production site and published so the design and its reasoning are copyable. Read the code,
> understand the trade-offs below, adapt it, and take responsibility for your own threat
> model. If you find a real flaw, please open an issue — but do not deploy this expecting
> someone else to maintain it for you.

---

## Why passkeys for a CMS admin route

A human-memorable shared secret is the weakest thing that could guard commit access. And
typing it into the browser's native Basic Auth prompt on every visit is exactly enough
friction to encourage bad habits — a short password, the same password as something else,
a password saved into a browser profile you also use elsewhere.

Passkeys invert that. The common path becomes a fingerprint, which is *less* friction than
the password ever was, and the password gets demoted to a rarely-touched recovery role
where being long and random costs nothing. The credential is phishing-resistant and
origin-bound: it cannot be replayed against a lookalike domain, because the browser will
not offer it there.

The secondary benefit is that there is now a *record*. Every credential change emits an
out-of-band alert, so an enrollment you did not perform is something you find out about.

---

## Quick start

Requires **Node 22.6+** (the test suite uses `--experimental-strip-types`).

```bash
npm install
cp .env.example .env.local
npm run dev
```

Out of the box, with an empty `.env.local`, `KEYSTATIC_AUTH_MODE` is unset, which means
**`basic`** — the gate behaves exactly like a plain Basic Auth password prompt, and
passkeys are entirely inert. That is the intended default. See
[Turning it on](#turning-it-on) below.

```bash
npm test        # enrollment policy tests
npm run typecheck
npm run build
```

---

## Request flow

`middleware.ts` gates everything under `/keystatic` and `/api/keystatic`, in this order:

1. **Fail-closed precheck** — missing `KEYSTATIC_SESSION_SECRET` in passkey mode ⇒ 503 for
   everyone. No password *and* no Redis ⇒ 503, since nobody could possibly authenticate.
2. **Session cookie** — a valid `ks_session` ⇒ pass through.
3. **Rate limit** — unauthenticated requests only (20 per 10 min per IP).
4. **Break-glass Basic Auth** — constant-time password comparison.
5. **Deny** — 307 to `/auth/keystatic` for navigations, 401 JSON for `/api/*`.

The rate limiter sits *behind* the session check deliberately. Metering every `/keystatic`
request against 20/10min throttles normal editing, because Keystatic's admin UI is chatty.
It now meters login attempts only.

An earlier version of this middleware had a real hole: with the password env var unset it
fell through to the bottom and left `/keystatic` wide open — an unset variable silently
disabled the entire gate. The precheck now denies instead. **A gate that cannot be enforced
must deny, not pass.**

---

## Key files

| File                                   | Role                                                            |
| -------------------------------------- | --------------------------------------------------------------- |
| `middleware.ts`                        | The edge gate. Auth-mode switch near the top.                   |
| `lib/auth/session.ts`                  | Stateless HMAC-SHA256 `ks_session` cookie. Edge-safe.           |
| `lib/auth/guard.ts`                    | `requireAdmin`, `checkOrigin`, `checkContentType`, rate bucket. |
| `lib/auth/enrollment.ts`               | `enrollmentBlockedReason` — the step-up rule. Pure, tested.     |
| `lib/auth/next-param.ts`               | `safeNext` open-redirect guard for `?next=`.                    |
| `lib/auth/notify.ts`                   | Best-effort alerts on credential changes.                       |
| `lib/webauthn/config.ts`               | rpID / origin pinning per environment.                          |
| `lib/webauthn/store.ts`                | Redis credential + challenge storage. Owns every `ks:*` key.    |
| `lib/site.ts`                          | The single place your hostname is configured.                   |
| `app/api/auth/**`                      | 8 route handlers, all `runtime = 'nodejs'`.                     |
| `app/auth/keystatic/{page,layout}.tsx` | Login UI.                                                       |
| `app/auth/keystatic/enroll/page.tsx`   | Device management.                                              |

`lib/auth/session.ts` uses only Web Crypto and `atob`/`btoa` — nothing Node-specific —
because it runs in Edge middleware. `verifySession` returns `null` on any problem and never
throws: an exception in Edge middleware fails the request unpredictably.

---

## Environment variables

| Var                          | Required | Notes                                                                                                |
| ---------------------------- | -------- | ---------------------------------------------------------------------------------------------------- |
| `KEYSTATIC_AUTH_MODE`        | no       | **Defaults to `basic`.** Only the literal string `passkey` turns passkeys on.                        |
| `KEYSTATIC_SESSION_SECRET`   | in passkey mode | `openssl rand -hex 32`. Missing ⇒ 503 on all `/keystatic`. Rotating it = session kill switch. |
| `KEYSTATIC_AUTH_PASSWORD`    | strongly recommended | Break-glass only. Long, random, in a password manager.                                  |
| `KEYSTATIC_ENROLL_TOKEN`     | no       | Bootstrap escape hatch, sent as `x-enroll-token`. Delete once a passkey exists.                      |
| `KEYSTATIC_RP_ID`            | in production | Your bare hostname. Defaults to `example.com`, so forgetting it fails closed.                    |
| `KEYSTATIC_RP_NAME`          | no       | Cosmetic name in the OS passkey prompt.                                                              |
| `KEYSTATIC_ADMIN_LABEL`      | no       | Cosmetic label for the single admin identity.                                                        |
| `UPSTASH_REDIS_REST_URL`     | for passkeys | Credential + challenge storage. WebAuthn routes 503 without it.                                  |
| `UPSTASH_REDIS_REST_TOKEN`   | for passkeys | As above. Set both or neither.                                                                   |
| `RESEND_API_KEY`             | no       | Alert email. Without it, alerts go to the log.                                                       |
| `KEYSTATIC_ALERT_EMAIL`      | no       | Where credential alerts go.                                                                          |
| `KEYSTATIC_ALERT_FROM`       | no       | Verified sender address for alerts.                                                                  |
| `KEYSTATIC_SECRET`           | github storage | Keystatic's own session secret — distinct from the gate's.                                     |
| `KEYSTATIC_GITHUB_CLIENT_ID` / `_SECRET` | github storage | Keystatic's GitHub OAuth app.                                                      |
| `KEYSTATIC_GITHUB_REPO_OWNER` / `_NAME`  | github storage | Which repo Keystatic commits to.                                                   |

`.env.example` carries the same information with more of the reasoning inline.

---

## Turning it on

The rollout is deliberately staged, because the failure mode of getting it wrong is locking
yourself out of your own CMS.

1. **Deploy with the defaults.** `KEYSTATIC_AUTH_MODE` unset ⇒ `basic` ⇒ nothing changes.
   Shipping the code is a no-op. Confirm the site still works.
2. **Set `KEYSTATIC_SESSION_SECRET`** (`openssl rand -hex 32`) and
   `KEYSTATIC_AUTH_PASSWORD`, plus the Upstash pair. Still `basic` mode; still no
   behavioural change.
3. **Set `KEYSTATIC_RP_ID`** to your real hostname.
4. **Enroll your first passkey.** Visit `/auth/keystatic/enroll`, type the break-glass
   password once, name the device, and add it. With zero credentials on file the password is
   sufficient — this is the bootstrap case.
5. **Enroll a second passkey**, on a different device. Do not skip this; see the limitations.
6. **Set `KEYSTATIC_AUTH_MODE=passkey`** and redeploy. `/keystatic` now redirects to the
   passkey page.

To roll back, unset `KEYSTATIC_AUTH_MODE`. There is no data migration in either direction —
the credentials simply sit unused in Redis.

### If you lose every device

The break-glass password will still let you *log in*, but it will not let you *enroll*. That
is the step-up rule doing its job. To recover:

1. Set `KEYSTATIC_ENROLL_TOKEN` (`openssl rand -hex 32`) in your deployment environment.
2. Enroll a new passkey, sending that value in the `x-enroll-token` header.
3. **Delete the token again.**

Only whoever controls the deployment environment can do this, which is the point.

---

## The security model

### `KEYSTATIC_AUTH_MODE` defaults to `basic`

Installing this code changes nothing until you deliberately opt in. If the default were
`passkey`, the deploy that shipped this file would 503 `/keystatic` the moment it landed —
before `KEYSTATIC_SESSION_SECRET` existed in the environment. Opt in, never by accident.

### Enrollment is passkey step-up, not password-gated

**The single most important rule in this repo.** Once *any* passkey exists, the break-glass
password can no longer mint a new credential — only an existing passkey-proved session or
`KEYSTATIC_ENROLL_TOKEN` can.

Without this, a leaked or guessed password would let an attacker enroll their own permanent
passkey: a foothold that *survives rotating the password*. You would rotate the secret,
believe you had evicted them, and be wrong.

The session cookie's `m` claim (`'passkey' | 'password'`) distinguishes the two. The rule
lives in `lib/auth/enrollment.ts` as a pure function with no I/O so it can be tested
directly, and it is enforced independently at **both** `/register/options` and
`/register/verify` — the options endpoint is a separate request, and its verdict must not be
the only thing standing between a caller and a stored credential.

The cost is the recovery dance described above. That is a deliberate trade.

### `KEYSTATIC_SESSION_SECRET` is a kill switch

Sessions are signed, not stored, so individual sessions cannot be revoked. The revocation
primitive is rotating this secret, which invalidates every outstanding session at once on
the next request. TTL is 12 hours.

### Stateless session cookie, not Redis-backed

Middleware runs on every `/api/keystatic/*` call and the admin UI is chatty, so a
per-request Upstash round-trip would be slow — and an Upstash outage would become a total
lockout. The trade-off is the loss of per-session revocation, mitigated by the kill switch
above and the short TTL.

### One shared `keystatic:pw` rate-limit bucket, inside `requireAdmin`

Not per-route. A security review found `/webauthn/credentials` and
`/webauthn/register/verify` calling `requireAdmin` with no limiter attached, which gave an
unthrottled brute-force oracle for the break-glass password via distinguishable status
codes. Metering now happens *inside* `requireAdmin`, before any comparison, and only when a
secret was actually offered — so session-cookie traffic never consumes the budget.

### Clone detection happens after signature verification

Per WebAuthn §6.1.1, a signature counter that fails to advance means the same credential is
in use from two places. When that happens the credential is *suspended*, not merely refused.

The ordering matters and was a real bug. `@simplewebauthn/server` v13 throws its own counter
error **before** it verifies the signature, so passing the stored counter to the library
would let an *unsigned, forged* assertion trip clone detection and disable a legitimate
credential — a remote denial-of-service on your own admin access. So the library is handed
`counter: 0` (disabling its check) and the comparison is redone afterwards, on
`verification.authenticationInfo.newCounter`, which only exists once the signature is proven.

Equally important: suspension is **never** inferred from the library's exception text. The
wording is not API surface. A reworded upstream message would silently disable clone
detection, and an unrelated error that happened to mention "counter" would brick a real
hardware key.

### The COSE public key is stored as a string

```ts
/**
 * base64url of the COSE public key. MUST be a string: Upstash serialises to
 * JSON, and a raw Uint8Array round-trips as {"0":4,"1":167,…} — silently
 * corrupting the key and failing every subsequent assertion.
 */
```

This landmine fails silently and late. Enrollment succeeds, the credential looks fine in the
manage UI, and only the *next* authentication attempt breaks — with a signature error
pointing nowhere near the cause. Anything binary going into Upstash needs the same
treatment.

### Other decisions

- **`SameSite=Lax`, not `Strict`.** Keystatic's GitHub OAuth callback arrives as a top-level
  cross-site GET. `Strict` would drop the cookie and 401 the handoff.
- **No `WWW-Authenticate` header in passkey mode.** It would pop the browser's native prompt
  instead of the passkey page. `?basic=1` opts back in for a no-JS emergency.
- **The login page lives at `/auth/keystatic`, outside the `/keystatic` prefix.** Naming it
  `/keystatic/login` would match `startsWith('/keystatic')` and cause a redirect loop.
- **`checkOrigin` rejects `*.vercel.app` in production**, accepting it only when
  `VERCEL_ENV === 'preview'`. Accepting the shared domain in prod would admit any
  attacker-hosted page on it.
- **Challenges are burned atomically** with `GETDEL`, so a challenge cannot be replayed even
  under concurrent requests.
- **Verification errors are generic.** Echoing the library's text would distinguish "no such
  credential" from "bad signature" — an enumeration oracle.
- **Removing the last passkey is blocked** when no break-glass password is configured, and
  the check unlinks-then-relinks rather than reading first, because a read-then-delete races
  with a concurrent delete of a *different* credential.
- **The middleware matcher excludes by path prefix, not file extension.** Excluding
  `.png` and friends would drop auth and CSP on `/keystatic/*.png`.

---

## What is optional, and what you lose

This app runs with **neither** Redis nor an email provider configured. Both degrade rather
than crash, but both cost you something real.

| Missing                | Still works                              | What you lose                                                                                                     |
| ---------------------- | ---------------------------------------- | ------------------------------------------------------------------------------------------------------------------- |
| **Upstash Redis**      | Break-glass password login; the whole `basic` mode path | Passkeys entirely — no credential storage, so all WebAuthn routes return 503. **And all rate limiting**, including on password attempts. |
| **Resend / email**     | Everything                               | Out-of-band alerting. Events are written to the process log instead, which nobody reads at 3am.                     |

The fail-closed behaviours are kept regardless: no session secret in passkey mode still
503s, and no password *and* no Redis still 503s, because in that state nobody could
authenticate at all.

The Redis case deserves emphasis. Losing rate limiting turns `KEYSTATIC_AUTH_PASSWORD` into
an online-brute-forceable secret at whatever rate your host will serve. That is survivable
only because the password is supposed to be 32 random hex characters. If yours is
memorable, configure Upstash first.

Email uses `fetch` against the Resend REST API rather than the SDK, so there is no npm
dependency for it — swapping in Postmark, SES, or a Slack webhook means rewriting
`deliver()` in `lib/auth/notify.ts` and nothing else.

---

## Tests

```bash
npm test
```

Covers `lib/auth/enrollment.ts` — the step-up policy — which is the most security-critical
piece of *pure* logic in the repo and therefore the piece most worth pinning down. It runs
on `node:test` with `--experimental-strip-types`, importing the TypeScript source directly
with no build step. Requires Node 22.6+.

The rest of the system is I/O-bound (Redis, WebAuthn verification, Edge middleware) and is
not covered here; verifying it means exercising a real browser against a real deployment.

---

## Known limitations

- **Clone detection is weak.** The `suspended` flag on signature-counter regression only ever
  fires for hardware keys — iCloud Keychain and Google Password Manager passkeys always
  report `signCount: 0`, and zero on both sides is spec-legal. Treat it as a signal, not a
  control.
- **The Keystatic CSP still allows `script-src 'unsafe-inline'`.** Keystatic's admin bundle
  requires it. This is the main residual risk to cookie confidentiality, and the reason the
  session TTL stays at 12 hours rather than something longer.
- **Preview deploys are a separate credential namespace.** Passkeys enrolled on a
  `*.vercel.app` preview have that rpID and will not work on your production domain. Use the
  password on previews.
- **Origin comparison is a literal string match.** If you serve both `example.com` and
  `www.example.com`, only the one matching `KEYSTATIC_RP_ID` will work — pick one and
  redirect the other.
- **Keep at least two passkeys enrolled.** With one, losing that device drops you to the
  break-glass password, and the step-up rule means the password cannot add a replacement —
  you would need `KEYSTATIC_ENROLL_TOKEN`.
- **There is exactly one admin.** No user table, no roles: reaching `/keystatic` at all means
  you are the admin. Multiple distinct admins would need a per-user handle in
  `lib/webauthn/config.ts` and an owner field in the credential store.
- **`getIP` trusts `x-vercel-forwarded-for`.** Deploying elsewhere means replacing that with
  whichever header your platform sets and guarantees to overwrite. The fallback headers are
  client-spoofable and are used only because spoofable rate limiting beats none.

---

## License

MIT — see [LICENSE](./LICENSE).
