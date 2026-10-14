import type { Metadata } from 'next';

// Shared Open Graph defaults. Next.js merges metadata shallowly, so any page
// that sets its own `openGraph` must spread this to keep the image and site info.
export const baseOpenGraph: NonNullable<Metadata['openGraph']> = {
  type: 'website',
  locale: 'en_US',
  siteName: 'GoSQLX',
  title: 'GoSQLX: Go SQL Parser, Formatter & Linter',
  description:
    'High-performance, zero-copy SQL parser, formatter and linter for Go with 8-dialect support.',
  images: [{ url: '/images/og-image.png', width: 1200, height: 630, alt: 'GoSQLX' }],
};
