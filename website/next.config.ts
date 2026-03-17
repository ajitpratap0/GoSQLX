import type { NextConfig } from 'next';
import withBundleAnalyzer from '@next/bundle-analyzer';

const withAnalyzer = withBundleAnalyzer({
  enabled: process.env.ANALYZE === 'true',
});

const nextConfig: NextConfig = {
  trailingSlash: true,
  async headers() {
    return [
      {
        source: '/(.*)',
        headers: [
          {
            key: 'Content-Security-Policy',
            value: "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval' 'wasm-unsafe-eval'; style-src 'self' 'unsafe-inline'; font-src 'self'; img-src 'self' https://img.shields.io https://goreportcard.com https://*.shields.io data:; connect-src 'self'; worker-src 'self' blob:",
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
  async redirects() {
    return [
      { source: '/docs/getting_started', destination: '/docs/getting-started', permanent: true },
      { source: '/docs/usage_guide', destination: '/docs/usage-guide', permanent: true },
      { source: '/docs/api_reference', destination: '/docs/api-reference', permanent: true },
      { source: '/docs/cli_guide', destination: '/docs/cli-guide', permanent: true },
      { source: '/docs/error_codes', destination: '/docs/error-codes', permanent: true },
      { source: '/docs/sql_compatibility', destination: '/docs/sql-compatibility', permanent: true },
      { source: '/docs/linting_rules', destination: '/docs/linting-rules', permanent: true },
      { source: '/docs/lsp_guide', destination: '/docs/lsp-guide', permanent: true },
      { source: '/docs/mcp_guide', destination: '/docs/mcp-guide', permanent: true },
      { source: '/docs/production_guide', destination: '/docs/production-guide', permanent: true },
      { source: '/docs/performance_tuning', destination: '/docs/performance-tuning', permanent: true },
    ];
  },
};

export default withAnalyzer(nextConfig);
