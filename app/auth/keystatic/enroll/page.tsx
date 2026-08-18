'use client';

import { startRegistration, browserSupportsWebAuthn } from '@simplewebauthn/browser';
import Link from 'next/link';
import { useCallback, useEffect, useState } from 'react';

type Status = {
  configured: boolean;
  passkeysAvailable: boolean;
  passwordEnabled: boolean;
  enrolledCount: number;
  sessionActive: boolean;
  sessionMethod: 'passkey' | 'password' | null;
  canEnroll: boolean;
};

type Credential = {
  id: string;
  shortId: string;
  label: string;
  deviceType: string;
  backedUp: boolean;
  createdAt: number;
  lastUsedAt: number | null;
  suspended: boolean;
};

const JSON_HEADERS = { 'Content-Type': 'application/json' };

function when(ts: number | null): string {
  if (!ts) return 'never';
  return new Date(ts).toLocaleDateString('en-US', {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
  });
}

export default function EnrollPage() {
  const [status, setStatus] = useState<Status | null>(null);
  const [credentials, setCredentials] = useState<Credential[] | null>(null);
  const [label, setLabel] = useState('');
  const [password, setPassword] = useState('');
  const [state, setState] = useState<'idle' | 'sending' | 'error'>('idle');
  const [error, setError] = useState('');
  const [supported, setSupported] = useState(true);

  const loadCredentials = useCallback(async () => {
    const res = await fetch('/api/auth/webauthn/credentials');
    if (!res.ok) {
      setCredentials(null);
      return;
    }
    const data = (await res.json()) as { credentials: Credential[] };
    setCredentials(data.credentials);
  }, []);

  const refresh = useCallback(async () => {
    const res = await fetch('/api/auth/status');
    const data = (await res.json()) as Status;
    setStatus(data);
    if (data.sessionActive) await loadCredentials();
  }, [loadCredentials]);

  useEffect(() => {
    setSupported(browserSupportsWebAuthn());
    refresh().catch(() => setStatus(null));
  }, [refresh]);

  async function addDevice(e: React.FormEvent) {
    e.preventDefault();
    setState('sending');
    setError('');
    try {
      const optionsRes = await fetch('/api/auth/webauthn/register/options', {
        method: 'POST',
        headers: JSON_HEADERS,
        body: JSON.stringify(password ? { password } : {}),
      });
      if (!optionsRes.ok) throw new Error((await optionsRes.json()).error ?? 'failed');
      const optionsJSON = await optionsRes.json();

      const attestation = await startRegistration({ optionsJSON });

      const verifyRes = await fetch('/api/auth/webauthn/register/verify', {
        method: 'POST',
        headers: JSON_HEADERS,
        body: JSON.stringify({
          response: attestation,
          label: label.trim() || 'unnamed device',
          ...(password ? { password } : {}),
        }),
      });
      if (!verifyRes.ok) throw new Error((await verifyRes.json()).error ?? 'failed');

      setLabel('');
      setPassword('');
      setState('idle');
      await refresh();
    } catch (err) {
      setState('error');
      if (err instanceof Error && err.name === 'InvalidStateError') {
        setError('this device is already enrolled.');
      } else {
        setError(err instanceof Error ? err.message : 'could not enroll');
      }
    }
  }

  async function revoke(id: string) {
    setError('');
    const res = await fetch(
      `/api/auth/webauthn/credentials?id=${encodeURIComponent(id)}`,
      {
        method: 'DELETE',
      }
    );
    if (!res.ok) {
      setState('error');
      setError((await res.json()).error ?? 'could not remove');
      return;
    }
    await refresh();
  }

  async function logout() {
    await fetch('/api/auth/logout', { method: 'POST', headers: JSON_HEADERS });
    await refresh();
    setCredentials(null);
  }

  return (
    <>
      <h1 className="font-medium text-2xl tracking-tight">passkeys</h1>

      {status && !status.passkeysAvailable && (
        <p className="text-sm text-red-400">
          passkeys are unavailable — Upstash Redis is not configured.
        </p>
      )}
      {!supported && (
        <p className="text-sm text-red-400">this browser does not support passkeys.</p>
      )}

      {credentials && credentials.length > 0 && (
        <ul className="flex flex-col gap-3">
          {credentials.map((c) => (
            <li
              key={c.id}
              className="flex items-start justify-between gap-4 border-b border-gray-100 dark:border-zinc-900 pb-3"
            >
              <div className="min-w-0">
                <p className="text-sm text-gray-800 dark:text-zinc-200 truncate">
                  {c.label}
                  {c.suspended && <span className="text-red-400"> · suspended</span>}
                </p>
                <p className="text-xs text-gray-400 dark:text-zinc-600">
                  {c.deviceType === 'multiDevice' ? 'synced' : 'this device only'} · added{' '}
                  {when(c.createdAt)} · last used {when(c.lastUsedAt)}
                </p>
              </div>
              <button
                type="button"
                onClick={() => revoke(c.id)}
                className="text-xs text-gray-400 dark:text-zinc-500 hover:text-red-400 transition-colors shrink-0"
              >
                remove
              </button>
            </li>
          ))}
        </ul>
      )}

      {status && !status.canEnroll && (
        <p className="text-sm text-gray-500 dark:text-zinc-400">
          a passkey already exists, so adding another device needs an existing passkey —
          the password alone will not do it.{' '}
          <Link href="/auth/keystatic" className="hover:text-blue-500 transition-colors">
            unlock with a passkey
          </Link>
          , then come back.
        </p>
      )}

      {status?.canEnroll && status.enrolledCount === 0 && status.passwordEnabled && (
        <p className="text-sm text-gray-500 dark:text-zinc-400">
          first device: enter the password once to enroll it.
        </p>
      )}

      <form onSubmit={addDevice} className="flex flex-col gap-4">
        {status?.canEnroll &&
          status.sessionActive === false &&
          status.passwordEnabled && (
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="password"
              aria-label="password"
              autoComplete="current-password"
              className="w-full bg-transparent border-b border-gray-200 dark:border-zinc-800 pb-2 text-sm text-gray-800 dark:text-zinc-200 placeholder-gray-300 dark:placeholder-zinc-700 focus:outline-none focus:border-gray-400 dark:focus:border-zinc-600 transition-colors"
            />
          )}
        <input
          type="text"
          value={label}
          onChange={(e) => setLabel(e.target.value)}
          placeholder="device name (e.g. laptop touch id)"
          aria-label="device name"
          maxLength={64}
          className="w-full bg-transparent border-b border-gray-200 dark:border-zinc-800 pb-2 text-sm text-gray-800 dark:text-zinc-200 placeholder-gray-300 dark:placeholder-zinc-700 focus:outline-none focus:border-gray-400 dark:focus:border-zinc-600 transition-colors"
        />
        <button
          type="submit"
          disabled={
            state === 'sending' ||
            !supported ||
            !status?.passkeysAvailable ||
            !status?.canEnroll
          }
          className="self-end text-sm text-gray-400 dark:text-zinc-500 hover:text-gray-900 dark:hover:text-zinc-100 disabled:opacity-30 transition-colors tracking-tight"
        >
          {state === 'sending' ? 'waiting...' : 'add this device →'}
        </button>
      </form>

      {state === 'error' && <p className="text-xs text-red-400">{error}</p>}

      <p className="flex gap-4 text-xs text-gray-300 dark:text-zinc-700">
        <Link href="/keystatic" className="hover:text-blue-500 transition-colors">
          keystatic
        </Link>
        {status?.sessionActive && (
          <button
            type="button"
            onClick={logout}
            className="hover:text-blue-500 transition-colors"
          >
            log out
          </button>
        )}
      </p>
    </>
  );
}
