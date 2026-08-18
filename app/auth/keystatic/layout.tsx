export const dynamic = 'force-dynamic';

import type { Metadata } from 'next';

export const metadata: Metadata = {
  title: 'unlock',
  robots: { index: false, follow: false },
};

export default function KeystaticAuthLayout({ children }: { children: React.ReactNode }) {
  return (
    <div className="min-h-screen flex items-center justify-center p-8">
      <main className="w-full max-w-[40ch] space-y-6">{children}</main>
    </div>
  );
}
