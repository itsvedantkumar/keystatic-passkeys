import { NextRequest, NextResponse } from 'next/server';
import { clearSessionCookie } from '@/lib/auth/session';
import { checkOrigin, jsonError } from '@/lib/auth/guard';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

export async function POST(req: NextRequest): Promise<NextResponse> {
  if (!checkOrigin(req)) return jsonError(403, 'bad origin');

  return NextResponse.json(
    { ok: true },
    { headers: { 'Set-Cookie': clearSessionCookie(), 'Cache-Control': 'no-store' } }
  );
}
