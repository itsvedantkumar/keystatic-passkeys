'use client';

import { startAuthentication, browserSupportsWebAuthn } from '@simplewebauthn/browser';
import Link from 'next/link';
import { useEffect, useState } from 'react';
import { safeNext } from '@/lib/auth/next-param';

type Status = {
  configured: boolean;
  passkeysAvailable: boolean;
  passwordEnabled: boolean;
  enrolledCount: number;
  sessionActive: boolean;
};

const JSON_HEADERS = { 'Content-Type': 'application/json' };

export default function KeystaticLoginPage() {
  const [status, setStatus] = useState<Status | null>(null);
  const [state, setState] = useState<'idle' | 'sending' | 'error'>('idle');
  const [error, setError] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [password, setPassword] = useState('');
  const [supported, setSupported] = useState(true);

  useEffect(() => {
    setSupported(browserSupportsWebAuthn());
    fetch('/api/auth/status')
      .then((r) => r.json())
      .then(setStatus)
      .catch(() => setStatus(null));
  }, []);

  function done() {
    // Full navigation, not a client route push — middleware has to see the cookie.
    window.location.href = safeNext(
      new URLSearchParams(window.location.search).get('next')
    );
  }

  async function unlockWithPasskey() {
    setState('sending');
    setError('');
    try {
      const optionsRes = await fetch('/api/auth/webauthn/authenticate/options', {
        method: 'POST',
        headers: JSON_HEADERS,
        body: '{}',
      });
      if (!optionsRes.ok) throw new Error((await optionsRes.json()).error ?? 'failed');
      const optionsJSON = await optionsRes.json();

      const assertion = await startAuthentication({ optionsJSON });

      const verifyRes = await fetch('/api/auth/webauthn/authenticate/verify', {
        method: 'POST',
        headers: JSON_HEADERS,
        body: JSON.stringify(assertion),
      });
      if (!verifyRes.ok) throw new Error((await verifyRes.json()).error ?? 'failed');
      done();
    } catch (err) {
      setState('error');
      setError(err instanceof Error ? err.message : 'could not unlock');
    }
  }

  async function unlockWithPassword(e: React.FormEvent) {
    e.preventDefault();
    if (!password) return;
    setState('sending');
    setError('');
    try {
      const res = await fetch('/api/auth/password', {
        method: 'POST',
        headers: JSON_HEADERS,
        body: JSON.stringify({ password }),
      });
      if (!res.ok) throw new Error((await res.json()).error ?? 'failed');
      done();
    } catch (err) {
      setState('error');
      setError(err instanceof Error ? err.message : 'could not unlock');
    }
  }

  const canUsePasskey =
    supported && (status?.passkeysAvailable ?? false) && (status?.enrolledCount ?? 0) > 0;

  return (
    <>
      <h1 className="font-medium text-2xl tracking-tight">unlock keystatic</h1>

      {status && !status.configured && (
        <p className="text-sm text-red-400">
          auth is not configured — KEYSTATIC_SESSION_SECRET is missing.
        </p>
      )}

      {canUsePasskey && (
        <button
          type="button"
          onClick={unlockWithPasskey}
          disabled={state === 'sending'}
          className="w-full border border-gray-200 dark:border-zinc-800 rounded-lg px-4 py-3 text-sm text-gray-800 dark:text-zinc-200 hover:border-gray-400 dark:hover:border-zinc-600 disabled:opacity-30 transition-colors tracking-tight"
        >
          {state === 'sending' ? 'waiting for passkey...' : 'unlock with passkey →'}
        </button>
      )}

      {status && !canUsePasskey && (
        <p className="text-sm text-gray-500 dark:text-zinc-400">
          {!supported
            ? 'this browser does not support passkeys.'
            : status.enrolledCount === 0
              ? 'no passkeys enrolled yet.'
              : 'passkeys are unavailable right now.'}
        </p>
      )}

      {status?.passwordEnabled &&
        (showPassword ? (
          <form onSubmit={unlockWithPassword} className="flex flex-col gap-4">
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="password"
              aria-label="password"
              autoComplete="current-password"
              autoFocus
              className="w-full bg-transparent border-b border-gray-200 dark:border-zinc-800 pb-2 text-sm text-gray-800 dark:text-zinc-200 placeholder-gray-300 dark:placeholder-zinc-700 focus:outline-none focus:border-gray-400 dark:focus:border-zinc-600 transition-colors"
            />
            <button
              type="submit"
              disabled={!password || state === 'sending'}
              className="self-end text-sm text-gray-400 dark:text-zinc-500 hover:text-gray-900 dark:hover:text-zinc-100 disabled:opacity-30 transition-colors tracking-tight"
            >
              unlock →
            </button>
          </form>
        ) : (
          <button
            type="button"
            onClick={() => setShowPassword(true)}
            className="text-sm text-gray-400 dark:text-zinc-500 hover:text-gray-900 dark:hover:text-zinc-100 transition-colors tracking-tight"
          >
            use password instead
          </button>
        ))}

      {state === 'error' && <p className="text-xs text-red-400">{error}</p>}

      <p className="text-xs text-gray-300 dark:text-zinc-700">
        <Link
          href="/auth/keystatic/enroll"
          className="hover:text-blue-500 transition-colors"
        >
          manage devices
        </Link>
      </p>
    </>
  );
}
