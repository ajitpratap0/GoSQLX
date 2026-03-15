import type { NextConfig } from 'next';

const nextConfig: NextConfig = {
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

export default nextConfig;
