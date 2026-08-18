// Module customization hook: rewrites the repo's "@/*" tsconfig path alias to
// a real file URL so `node --test` can resolve source imports like
// `@/lib/auth/enrollment`. Next.js/webpack handle this alias separately at
// build time — this is test-only plumbing, not a runtime behavior change.
const repoRoot = new URL('../', import.meta.url);

export async function resolve(specifier, context, nextResolve) {
  if (specifier.startsWith('@/')) {
    const rest = specifier.slice(2);
    const target = new URL(/\.[a-z]+$/i.test(rest) ? rest : `${rest}.ts`, repoRoot);
    return nextResolve(target.href, context);
  }
  return nextResolve(specifier, context);
}
