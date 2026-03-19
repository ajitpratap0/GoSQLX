import type { Metadata } from 'next';
import Link from 'next/link';

export const metadata: Metadata = {
  title: '404 - Page Not Found',
  robots: { index: false, follow: false },
};

export default function NotFound() {
  return (
    <main id="main-content" className="min-h-screen flex items-center justify-center">
      <div className="text-center">
        <p className="text-sm font-semibold text-emerald-400 uppercase tracking-wider mb-4">404</p>
        <h1 className="text-4xl font-bold tracking-tight text-white mb-4">
          Page not found
        </h1>
        <p className="text-lg text-zinc-400 mb-8">
          The page you&apos;re looking for doesn&apos;t exist.
        </p>
        <Link
          href="/"
          className="inline-flex items-center gap-2 rounded-lg bg-emerald-500 px-5 py-2.5 text-sm font-semibold text-white shadow-sm hover:bg-emerald-400 transition-colors"
        >
          Back to Home
        </Link>
      </div>
    </main>
  );
}
