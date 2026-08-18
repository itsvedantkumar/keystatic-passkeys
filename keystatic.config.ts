import { config, fields, collection } from '@keystatic/core';

/**
 * Deliberately tiny. The point of this repo is the passkey gate in
 * middleware.ts, not the CMS schema — one collection is enough to prove the
 * admin UI is reachable once you are authenticated, and unreachable when you
 * are not.
 *
 * Storage is `local` in development (writes straight to ./content) and `github`
 * in production. The GitHub mode is what makes the gate matter: reaching
 * /keystatic in production is effectively git write access to the content repo.
 * It is also the reason the session cookie is SameSite=Lax rather than Strict —
 * Keystatic's OAuth callback arrives as a top-level cross-site GET.
 */
const repoOwner = process.env.KEYSTATIC_GITHUB_REPO_OWNER || 'your-org';
const repoName = process.env.KEYSTATIC_GITHUB_REPO_NAME || 'your-repo';

export default config({
  storage:
    process.env.NODE_ENV === 'development'
      ? { kind: 'local' as const }
      : {
          kind: 'github' as const,
          repo: { owner: repoOwner, name: repoName },
        },
  ui: {
    brand: {
      name: 'Keystatic Passkeys',
    },
  },
  collections: {
    notes: collection({
      label: 'Notes',
      slugField: 'title',
      path: 'content/notes/*',
      format: { contentField: 'content' },
      schema: {
        title: fields.slug({ name: { label: 'Title' } }),
        content: fields.document({
          label: 'Content',
          formatting: true,
          links: true,
        }),
      },
    }),
  },
});
