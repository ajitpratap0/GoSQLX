import type { Metadata } from 'next';
import Link from 'next/link';
import { FadeIn } from '@/components/ui/FadeIn';

export const metadata: Metadata = {
  title: '404 - Page Not Found',
  description: 'The page you are looking for does not exist. Return to the GoSQLX homepage.',
  robots: { index: false, follow: false },
};

export default function NotFound() {
  return (
    <div className="min-h-screen flex items-center justify-center">
      <div className="text-center">
        <FadeIn>
          <p className="text-sm font-semibold text-emerald-400 uppercase tracking-wider mb-4">404</p>
        </FadeIn>
        <FadeIn delay={0.1}>
          <h1 className="text-4xl font-bold tracking-tight text-white mb-4">
            Page not found
          </h1>
        </FadeIn>
        <FadeIn delay={0.2}>
          <p className="text-lg text-zinc-400 mb-8">
            The page you&apos;re looking for doesn&apos;t exist.
          </p>
        </FadeIn>
        <FadeIn delay={0.3}>
          <Link
            href="/"
            className="inline-flex items-center gap-2 rounded-lg bg-emerald-500 px-5 py-2.5 text-sm font-semibold text-white shadow-sm hover:bg-emerald-400 transition-colors"
          >
            Back to Home
          </Link>
        </FadeIn>
      </div>
    </div>
  );
}
