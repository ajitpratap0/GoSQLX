import { DOCS_SIDEBAR } from '@/lib/constants';
import { getAllDocs } from '@/lib/docs';
import { PROJECT, QA_CORPUS, BENCH_ENV, PARSE_BENCHMARKS, opsPerSec, formatOps } from '@/data/metrics';

export const SITE_URL = 'https://gosqlx.dev';

const REPO = 'https://github.com/ajitpratap0/GoSQLX';

export const TEXT_HEADERS = {
  'Content-Type': 'text/plain; charset=utf-8',
} as const;

const simple = PARSE_BENCHMARKS[0];

/** Summary block shared by llms.txt and llms-full.txt. Numbers come from src/data/metrics.ts. */
function header(): string[] {
  return [
    '# GoSQLX',
    '',
    '> High-performance SQL parsing SDK for Go: zero-copy tokenizer, recursive-descent parser, AST, formatter, linter and security scanner. Multi-dialect and race-free.',
    '',
    `GoSQLX is a production-ready SQL parsing library for Go with zero-copy tokenization, recursive-descent parsing and AST generation backed by object pooling. It supports ${PROJECT.dialectCount} dialects (PostgreSQL, MySQL, MariaDB, SQL Server, Oracle, SQLite, Snowflake, ClickHouse) and ships a CLI (\`gosqlx\`) for validation, formatting, linting, transpilation and security analysis. Apache-2.0 licensed. Requires ${PROJECT.minGo}.`,
    '',
    `Current stable version: ${PROJECT.version}`,
    `Website: ${SITE_URL}`,
    `Interactive Playground: ${SITE_URL}/playground/`,
    '',
    '## Key facts',
    '',
    `- SQL dialects: ${PROJECT.dialectCount}`,
    `- Built-in linter rules: ${PROJECT.lintRuleCount} (L001-L030)`,
    `- MCP server tools: ${PROJECT.mcpToolCount}`,
    `- SQL-99 compliance: ${PROJECT.sql99} (estimated)`,
    `- QA corpus (${QA_CORPUS.release}): Snowflake ${QA_CORPUS.snowflake.pass}/${QA_CORPUS.snowflake.total}, ClickHouse ${QA_CORPUS.clickhouse.pass}/${QA_CORPUS.clickhouse.total}`,
    `- Performance: ~${simple.nsPerOp} ns/op (~${formatOps(opsPerSec(simple.nsPerOp))} ops/sec) for a simple SELECT (${BENCH_ENV.stage}) on ${BENCH_ENV.hardware}, ${BENCH_ENV.goVersion}. This is the parse stage only (pre-tokenized input), not tokenize or end-to-end. Source: ${BENCH_ENV.source}.`,
    '',
  ];
}

/** Index of the documentation, grouped by sidebar category. */
export function buildLlmsTxt(): string {
  const lines = header();
  lines.push('## Documentation', '');
  for (const category of DOCS_SIDEBAR) {
    lines.push(`### ${category.category}`, '');
    for (const item of category.items) {
      lines.push(`- [${item.label}](${SITE_URL}/docs/${item.slug}/): ${item.description}`);
    }
    lines.push('');
  }
  lines.push(
    '## Optional',
    '',
    `- [Full documentation in one file](${SITE_URL}/llms-full.txt): Every docs page as plain text`,
    `- [Changelog](${SITE_URL}/blog/): Release notes for every version`,
    `- [Changelog feed](${SITE_URL}/blog/feed.xml): RSS 2.0`,
    `- [Source code](${REPO}): GitHub repository`,
    '- [Go package docs](https://pkg.go.dev/github.com/ajitpratap0/GoSQLX/pkg/gosqlx): pkg.go.dev reference',
    ''
  );
  return lines.join('\n');
}

/** Index summary followed by the full markdown of every docs page. */
export function buildLlmsFullTxt(): string {
  const parts = [header().join('\n')];
  for (const doc of getAllDocs()) {
    parts.push(
      [
        '---',
        '',
        `# ${doc.title}`,
        '',
        `Source: ${SITE_URL}/docs/${doc.slug}/`,
        '',
        doc.content.replace(/^\s*#\s+.+\n+/, '').trim(),
        '',
      ].join('\n')
    );
  }
  return parts.join('\n');
}
