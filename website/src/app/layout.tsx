import type { Metadata } from 'next';
import { instrumentSans, jetbrainsMono } from '@/lib/fonts';
import { Navbar } from '@/components/layout/Navbar';
import { Footer } from '@/components/layout/Footer';
import { ServiceWorkerRegister } from '@/components/ServiceWorkerRegister';
import './globals.css';

export const metadata: Metadata = {
  title: {
    default: 'GoSQLX - Production-Ready SQL Parsing SDK for Go',
    template: 'GoSQLX - %s',
  },
  description:
    'High-performance, zero-copy SQL parsing SDK for Go. Thread-safe with multi-dialect support for PostgreSQL, MySQL, SQLite, SQL Server, Oracle, and Snowflake.',
  metadataBase: new URL('https://gosqlx.dev'),
  alternates: {
    canonical: '/',
  },
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
  robots: {
    index: true,
    follow: true,
    googleBot: { index: true, follow: true },
  },
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en" className={`${instrumentSans.variable} ${jetbrainsMono.variable}`}>
      <body className="font-sans overflow-x-hidden">
        <a
          href="#main-content"
          className="sr-only focus:not-sr-only focus:absolute focus:top-4 focus:left-4 focus:z-50 focus:rounded-md focus:bg-white focus:px-4 focus:py-2 focus:text-sm focus:font-medium focus:text-black focus:shadow-lg focus:outline-none"
        >
          Skip to main content
        </a>
        <script
          type="application/ld+json"
          suppressHydrationWarning
          dangerouslySetInnerHTML={{
            __html: JSON.stringify({
              '@context': 'https://schema.org',
              '@type': 'SoftwareApplication',
              name: 'GoSQLX',
              applicationCategory: 'DeveloperApplication',
              operatingSystem: 'Any',
              url: 'https://gosqlx.dev',
              downloadUrl: 'https://github.com/ajitpratap0/GoSQLX/releases',
              codeRepository: 'https://github.com/ajitpratap0/GoSQLX',
              programmingLanguage: 'Go',
              description: 'High-performance, zero-copy SQL parsing SDK for Go',
              offers: {
                '@type': 'Offer',
                price: '0',
                priceCurrency: 'USD',
              },
              publisher: {
                '@type': 'Organization',
                name: 'GoSQLX',
                url: 'https://gosqlx.dev',
                sameAs: ['https://github.com/ajitpratap0/GoSQLX'],
              },
            }),
          }}
        />
        <Navbar />
        <main id="main-content" className="pt-16">{children}</main>
        <Footer />
        <ServiceWorkerRegister />
      </body>
    </html>
  );
}
