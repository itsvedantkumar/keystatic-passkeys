import { NextRequest, NextResponse } from 'next/server';
import { checkOrigin, jsonError, requireAdmin } from '@/lib/auth/guard';
import { notifySecurityEvent, requestContext } from '@/lib/auth/notify';
import { isPasswordConfigured } from '@/lib/webauthn/config';
import {
  countCredentials,
  deleteCredential,
  deleteCredentialRecord,
  getCredential,
  isRedisUnavailable,
  listCredentials,
  relinkCredentialId,
  unlinkCredentialId,
} from '@/lib/webauthn/store';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

const NO_STORE = { 'Cache-Control': 'no-store' };

/** Enrolled devices. Never returns publicKey. */
export async function GET(req: NextRequest): Promise<NextResponse> {
  const auth = await requireAdmin(req);
  if (!auth.ok) return jsonError(auth.status, auth.error);

  try {
    const credentials = (await listCredentials()).map((c) => ({
      id: c.id,
      shortId: c.id.slice(0, 12),
      label: c.label,
      deviceType: c.deviceType,
      backedUp: c.backedUp,
      createdAt: c.createdAt,
      lastUsedAt: c.lastUsedAt,
      suspended: c.suspended ?? false,
    }));
    return NextResponse.json({ credentials }, { headers: NO_STORE });
  } catch (err) {
    if (isRedisUnavailable(err)) return jsonError(503, 'passkeys unavailable');
    return jsonError(503, 'unavailable');
  }
}

export async function DELETE(req: NextRequest): Promise<NextResponse> {
  if (!checkOrigin(req)) return jsonError(403, 'bad origin');

  const auth = await requireAdmin(req);
  if (!auth.ok) return jsonError(auth.status, auth.error);

  const id = req.nextUrl.searchParams.get('id');
  if (!id) return jsonError(400, 'missing id');

  const removed = async () => {
    await notifySecurityEvent(
      'a passkey was removed',
      `A passkey was removed from /keystatic.\n\nid: ${id.slice(0, 12)}\n${requestContext(req)}`
    );
    return NextResponse.json({ ok: true }, { headers: NO_STORE });
  };

  try {
    if (!(await getCredential(id))) return jsonError(404, 'no such credential');

    if (isPasswordConfigured()) {
      await deleteCredential(id);
      return removed();
    }

    // Lockout guard: without a break-glass password, removing the last passkey
    // would make /keystatic permanently unreachable. Remove from the index
    // first and put it back if that emptied the set — a read-then-delete check
    // races with a concurrent delete of a *different* credential, and both
    // would pass while the set still held two.
    if (!(await unlinkCredentialId(id))) return jsonError(404, 'no such credential');
    if ((await countCredentials()) === 0) {
      await relinkCredentialId(id);
      return jsonError(
        409,
        'cannot remove the last passkey while password login is disabled'
      );
    }

    await deleteCredentialRecord(id);
    return removed();
  } catch (err) {
    if (isRedisUnavailable(err)) return jsonError(503, 'passkeys unavailable');
    return jsonError(503, 'unavailable');
  }
}
