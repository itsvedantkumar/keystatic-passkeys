import Link from 'next/link';

const AUTH_MODE = process.env.KEYSTATIC_AUTH_MODE === 'passkey' ? 'passkey' : 'basic';

export default function Home() {
  return (
    <main className="min-h-screen flex items-center justify-center p-8">
      <div className="w-full max-w-[60ch] space-y-6">
        <h1 className="font-medium text-2xl tracking-tight">keystatic-passkeys</h1>

        <p className="text-sm text-gray-600 dark:text-zinc-400">
          A reference implementation of a WebAuthn passkey gate in front of the Keystatic
          admin route. This home page exists only so the app has somewhere to render —
          everything interesting is in <code>middleware.ts</code>, <code>lib/auth/</code>{' '}
          and <code>lib/webauthn/</code>.
        </p>

        <p className="text-sm text-gray-600 dark:text-zinc-400">
          Auth mode is currently{' '}
          <strong className="text-gray-900 dark:text-zinc-200">{AUTH_MODE}</strong>.{' '}
          {AUTH_MODE === 'basic'
            ? 'Passkeys are off: /keystatic falls back to an HTTP Basic Auth prompt. Set KEYSTATIC_AUTH_MODE=passkey to opt in.'
            : 'Passkeys are on: /keystatic redirects to the unlock page.'}
        </p>

        <p className="flex gap-4 text-sm">
          <Link href="/keystatic" className="hover:text-blue-500 transition-colors">
            /keystatic →
          </Link>
          <Link href="/auth/keystatic" className="hover:text-blue-500 transition-colors">
            unlock →
          </Link>
          <Link
            href="/auth/keystatic/enroll"
            className="hover:text-blue-500 transition-colors"
          >
            manage passkeys →
          </Link>
        </p>
      </div>
    </main>
  );
}
