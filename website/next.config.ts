import type { NextConfig } from 'next';
import withBundleAnalyzer from '@next/bundle-analyzer';
import { withSentryConfig } from '@sentry/nextjs';
import { docsRedirects } from './src/lib/docs-redirects';

const withAnalyzer = withBundleAnalyzer({
  enabled: process.env.ANALYZE === 'true',
});

const nextConfig: NextConfig = {
  trailingSlash: true,
  images: {
    remotePatterns: [
      { protocol: 'https', hostname: 'img.shields.io' },
    ],
  },
  async headers() {
    return [
      {
        // Fixed, unversioned URLs: always revalidate (ETag makes it a cheap 304) so a
        // new deploy's gosqlx.wasm and its matching wasm_exec.js are never pinned stale.
        source: '/wasm/:path*',
        headers: [
          {
            key: 'Cache-Control',
            value: 'public, max-age=0, must-revalidate',
          },
        ],
      },
      {
        source: '/(.*)',
        headers: [
          {
            key: 'Content-Security-Policy',
            value: "default-src 'self'; script-src 'self' 'unsafe-inline' 'wasm-unsafe-eval' https://va.vercel-scripts.com; style-src 'self' 'unsafe-inline'; font-src 'self'; img-src 'self' https://img.shields.io https://goreportcard.com https://*.shields.io data:; connect-src 'self' https://*.sentry.io https://vitals.vercel-insights.com https://va.vercel-scripts.com; worker-src 'self' blob:; frame-ancestors 'none'; base-uri 'self'; form-action 'self'",
          },
          {
            key: 'Strict-Transport-Security',
            value: 'max-age=31536000; includeSubDomains; preload',
          },
          {
            key: 'Permissions-Policy',
            value: 'camera=(), microphone=(), geolocation=(), interest-cohort=()',
          },
          {
            key: 'X-Frame-Options',
            value: 'DENY',
          },
          {
            key: 'X-Content-Type-Options',
            value: 'nosniff',
          },
          {
            key: 'Referrer-Policy',
            value: 'strict-origin-when-cross-origin',
          },
        ],
      },
    ];
  },
  async rewrites() {
    // Raw-markdown alternates: /docs/<slug>.md is served by the /md/docs route handler.
    // Paths with an extension are exempt from the trailing-slash redirect.
    return {
      beforeFiles: [{ source: '/docs/:slug*.md', destination: '/md/docs/:slug*' }],
      afterFiles: [],
      fallback: [],
    };
  },
  async redirects() {
    return [
      // /blog was release notes only; it is now /changelog. Single hop, trailing slashes kept.
      { source: '/blog', destination: '/changelog/', permanent: true },
      { source: '/blog/feed.xml', destination: '/changelog/feed.xml', permanent: true },
      { source: '/blog/:slug', destination: '/changelog/:slug/', permanent: true },
      // Moved docs pages (IA restructure and legacy file-name URLs). Single hop, trailing slashes kept.
      ...docsRedirects(),
    ];
  },
};

export default withSentryConfig(
  withAnalyzer(nextConfig),
  {
    org: process.env.SENTRY_ORG,
    project: process.env.SENTRY_PROJECT,
    authToken: process.env.SENTRY_AUTH_TOKEN,
    widenClientFileUpload: true,
    tunnelRoute: '/monitoring',
    silent: !process.env.CI,
    // Tree-shaking disabled — using Turbopack which doesn't support webpack tree-shaking
  }
);
