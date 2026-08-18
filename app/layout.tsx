import './globals.css';
import type { Metadata, Viewport } from 'next';

export const viewport: Viewport = {
  width: 'device-width',
  initialScale: 1,
};

export const metadata: Metadata = {
  title: 'Keystatic Passkeys',
  description: 'Reference implementation of a WebAuthn gate for the Keystatic admin.',
  robots: { index: false, follow: false },
};

export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return (
    <html lang="en">
      <body className="antialiased tracking-tight dark:bg-zinc-950 bg-white text-gray-900 dark:text-zinc-200">
        {children}
      </body>
    </html>
  );
}
