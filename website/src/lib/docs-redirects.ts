/**
 * Docs URLs that moved, mapped to where they live now (paths under /docs/, no slashes
 * at either end). Every destination must be a current DOCS_SIDEBAR slug so each old
 * URL resolves in a single hop. Imported by next.config.ts, so keep this file free of
 * path aliases and runtime dependencies.
 */
export const MOVED_DOCS: Readonly<Record<string, string>> = {
  // 2026-10 IA restructure (Start / Guides / Integrations / Reference / Concepts / Migration)
  'api-reference': 'reference/api',
  'architecture': 'concepts/architecture',
  'configuration': 'reference/configuration',
  'error-codes': 'reference/error-codes',
  'sql-compatibility': 'reference/sql-compatibility',
  'linting-rules': 'reference/linting-rules',
  'lsp-guide': 'integrations/lsp',
  'mcp-guide': 'integrations/mcp',
  'security': 'concepts/security',
  'production-guide': 'guides/production',
  'performance-tuning': 'guides/performance-tuning',
  'tutorials/01-sql-validator-cicd': 'guides/sql-validator-cicd',
  'tutorials/02-custom-sql-formatter': 'guides/custom-sql-formatter',
  'editors/vscode': 'integrations/vscode',
  'editors/neovim': 'integrations/neovim',
  'editors/jetbrains': 'integrations/jetbrains',
  // Legacy upper-case file names (pre-2026 URLs, still linked from older READMEs)
  'getting_started': 'getting-started',
  'usage_guide': 'usage-guide',
  'api_reference': 'reference/api',
  'cli_guide': 'cli-guide',
  'error_codes': 'reference/error-codes',
  'sql_compatibility': 'reference/sql-compatibility',
  'linting_rules': 'reference/linting-rules',
  'lsp_guide': 'integrations/lsp',
  'mcp_guide': 'integrations/mcp',
  'production_guide': 'guides/production',
  'performance_tuning': 'guides/performance-tuning',
};

/** Permanent redirects for moved docs pages and their per-page OG images. */
export function docsRedirects(): { source: string; destination: string; permanent: true }[] {
  return Object.entries(MOVED_DOCS).flatMap(([from, to]) => [
    { source: `/docs/${from}`, destination: `/docs/${to}/`, permanent: true as const },
    { source: `/og/docs/${from}`, destination: `/og/docs/${to}/`, permanent: true as const },
  ]);
}
