import type { Metadata } from 'next';
import { instrumentSans, jetbrainsMono } from '@/lib/fonts';
import { Navbar } from '@/components/layout/Navbar';
import { Footer } from '@/components/layout/Footer';
import { Analytics } from '@vercel/analytics/next';
import './globals.css';

export const metadata: Metadata = {
  title: {
    default: 'GoSQLX - Production-Ready SQL Parsing SDK for Go',
    template: 'GoSQLX - %s',
  },
  description:
    'High-performance, zero-copy SQL parsing SDK for Go. Thread-safe with multi-dialect support for PostgreSQL, MySQL, SQLite, SQL Server, Oracle, and Snowflake.',
  metadataBase: new URL('https://gosqlx.dev'),
  openGraph: {
    type: 'website',
    locale: 'en_US',
    url: 'https://gosqlx.dev',
    siteName: 'GoSQLX',
    title: 'GoSQLX - Production-Ready SQL Parsing SDK for Go',
    description:
      'High-performance, zero-copy SQL parsing SDK for Go. Thread-safe with multi-dialect support.',
    images: [{ url: '/images/og-image.png', width: 1200, height: 630, alt: 'GoSQLX' }],
  },
  twitter: {
    card: 'summary_large_image',
    title: 'GoSQLX - Production-Ready SQL Parsing SDK for Go',
    description:
      'High-performance, zero-copy SQL parsing SDK for Go. Thread-safe with multi-dialect support.',
    images: ['/images/og-image.png'],
  },
  icons: {
    icon: '/favicon.png',
    apple: '/apple-touch-icon.png',
  },
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en" className={`${instrumentSans.variable} ${jetbrainsMono.variable}`}>
      <body className="font-sans">
        <Navbar />
        <div className="pt-16">{children}</div>
        <Footer />
        <Analytics />
      </body>
    </html>
  );
}
