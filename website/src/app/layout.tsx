import type { Metadata } from 'next';
import { inter, jetbrainsMono } from '@/lib/fonts';
import { Navbar } from '@/components/layout/Navbar';
import { Footer } from '@/components/layout/Footer';
import { Providers } from '@/components/Providers';
import { SpeedInsights } from '@vercel/speed-insights/next';
import { baseOpenGraph } from '@/lib/open-graph';
import './globals.css';

export const metadata: Metadata = {
  title: {
    default: 'GoSQLX: Go SQL Parser, Formatter & Linter',
    template: '%s | GoSQLX',
  },
  description:
    'High-performance, zero-copy SQL parser, formatter and linter for Go. Thread-safe with 8-dialect support: PostgreSQL, MySQL, MariaDB, SQL Server, Oracle, SQLite, Snowflake, and ClickHouse.',
  metadataBase: new URL('https://gosqlx.dev'),
  openGraph: baseOpenGraph,
  twitter: {
    card: 'summary_large_image',
    title: 'GoSQLX: Go SQL Parser, Formatter & Linter',
    description:
      'High-performance, zero-copy SQL parser, formatter and linter for Go with 8-dialect support.',
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
  // Google Search Console ownership (HTML tag method, #682).
  verification: {
    google: 'wYXXkeFTH-HVJGWHs8K-Hjf6b1YcdbmJ97Nvid1QhmY',
  },
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en" className={`dark ${inter.variable} ${jetbrainsMono.variable}`} suppressHydrationWarning>
      <head>
        <script
          dangerouslySetInnerHTML={{
            __html: `(function(){try{var t=localStorage.getItem('theme');if(t==='light'||(!t&&window.matchMedia('(prefers-color-scheme:light)').matches)){document.documentElement.classList.add('light');document.documentElement.classList.remove('dark')}else{document.documentElement.classList.add('dark');document.documentElement.classList.remove('light')}}catch(e){}})();`,
          }}
        />
      </head>
      <body className="font-sans overflow-x-clip">
        <a
          href="#main-content"
          className="sr-only focus:not-sr-only focus:absolute focus:top-4 focus:left-4 focus:z-50 focus:rounded-md focus:bg-fg focus:px-4 focus:py-2 focus:text-sm focus:font-medium focus:text-bg focus:shadow-lg focus:outline-none"
        >
          Skip to main content
        </a>
        <Providers>
          <Navbar />
          <main id="main-content" className="pt-16">{children}</main>
          <Footer />
        </Providers>
        <SpeedInsights />
      </body>
    </html>
  );
}
