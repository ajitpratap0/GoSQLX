import type { Metadata } from 'next';
import Link from 'next/link';
import { notFound } from 'next/navigation';
import { pageMeta } from '@/lib/seo';
import { JsonLd } from '@/components/JsonLd';
import { GlassCard } from '@/components/ui/GlassCard';
import { Button } from '@/components/ui/Button';
import { PROJECT } from '@/data/metrics';
import { COMPETITOR_RUN, competitorResult } from '@/data/competitor-metrics';
import { COMPETITOR_PAGES, getCompetitorPage } from '../competitors';

export const dynamicParams = false;

export function generateStaticParams() {
  return COMPETITOR_PAGES.map((c) => ({ competitor: c.slug }));
}

type Props = { params: Promise<{ competitor: string }> };

export async function generateMetadata({ params }: Props): Promise<Metadata> {
  const { competitor } = await params;
  const page = getCompetitorPage(competitor);
  if (!page) return {};
  return pageMeta({
    title: `${page.short} alternative for Go: GoSQLX compared`,
    description: page.description,
    path: `/compare/${page.slug}/`,
    absolute: true,
  });
}

function formatNs(ns: number): string {
  return `${Math.round(ns).toLocaleString('en-US')} ns`;
}

export default async function CompetitorComparePage({ params }: Props) {
  const { competitor } = await params;
  const page = getCompetitorPage(competitor);
  if (!page) notFound();

  const run = COMPETITOR_RUN;
  const measuredOn = run.generatedAt.slice(0, 10);
  const them = page.parserId ? run.parsers.find((p) => p.id === page.parserId) : undefined;
  const rows = them
    ? run.queries.map((q) => ({
        query: q,
        gosqlx: competitorResult(q.id, 'gosqlx'),
        other: competitorResult(q.id, them.id),
      }))
    : [];

  const url = `https://gosqlx.dev/compare/${page.slug}/`;
  const structuredData = {
    '@context': 'https://schema.org',
    '@graph': [
      {
        '@type': 'WebPage',
        '@id': `${url}#webpage`,
        url,
        name: `${page.short} alternative for Go: GoSQLX compared`,
        description: page.description,
        isPartOf: { '@id': 'https://gosqlx.dev/#website' },
      },
      {
        '@type': 'BreadcrumbList',
        itemListElement: [
          { '@type': 'ListItem', position: 1, name: 'Home', item: 'https://gosqlx.dev/' },
          { '@type': 'ListItem', position: 2, name: 'Compare', item: 'https://gosqlx.dev/compare/' },
          { '@type': 'ListItem', position: 3, name: page.short, item: url },
        ],
      },
    ],
  };

  const link = 'text-accent underline underline-offset-2';

  return (
    <div className="min-h-screen">
      <JsonLd data={structuredData} />
      <section className="section-padding pt-24 pb-10">
        <div className="container-width max-w-3xl">
          <p className="text-sm text-fg-muted">
            <Link href="/compare/" className={link}>
              Compare
            </Link>{' '}
            / {page.short}
          </p>
          <h1 className="mt-3 text-4xl font-bold tracking-tight text-fg">
            {page.short} alternative: GoSQLX compared
          </h1>
          <p className="mt-4 text-lg text-fg-muted">{page.summary}</p>
        </div>
      </section>

      <section className="section-padding pb-10">
        <div className="container-width max-w-3xl">
          <GlassCard className="p-6" hover={false}>
            <dl className="grid gap-3 text-sm sm:grid-cols-[10rem_1fr]">
              {page.facts.map((f) => (
                <div key={f.label} className="contents">
                  <dt className="font-medium text-fg">{f.label}</dt>
                  <dd className="text-fg-muted">{f.value}</dd>
                </div>
              ))}
              <div className="contents">
                <dt className="font-medium text-fg">Source</dt>
                <dd className="text-fg-muted">
                  <a href={page.repo} className={link} rel="noopener noreferrer">
                    {page.repo.replace('https://', '')}
                  </a>
                </dd>
              </div>
              {page.maintenance && (
                <div className="contents">
                  <dt className="font-medium text-fg">Maintenance</dt>
                  <dd className="text-fg-muted">
                    <a href={page.maintenance.href} className={link} rel="noopener noreferrer">
                      {page.maintenance.text}
                    </a>
                  </dd>
                </div>
              )}
            </dl>
          </GlassCard>
        </div>
      </section>

      <section className="section-padding pb-10">
        <div className="container-width max-w-3xl grid gap-6 md:grid-cols-2">
          <GlassCard className="p-6" hover={false}>
            <h2 className="text-lg font-bold text-fg">Pick {page.short} when</h2>
            <ul className="mt-3 list-disc pl-5 space-y-2 text-sm text-fg-muted">
              {page.pickThem.map((t) => (
                <li key={t}>{t}</li>
              ))}
            </ul>
          </GlassCard>
          <GlassCard className="p-6" hover={false}>
            <h2 className="text-lg font-bold text-fg">Pick GoSQLX when</h2>
            <ul className="mt-3 list-disc pl-5 space-y-2 text-sm text-fg-muted">
              {page.pickGoSQLX.map((t) => (
                <li key={t}>{t}</li>
              ))}
            </ul>
          </GlassCard>
        </div>
      </section>

      {them && (
        <section className="section-padding pb-10">
          <div className="container-width max-w-3xl">
            <h2 className="text-2xl font-bold text-fg mb-2">Parse speed, measured</h2>
            <p className="text-sm text-fg-muted mb-4">
              End-to-end stage (SQL text to AST) &middot; {run.hardware.cpu} ({run.hardware.goos}/
              {run.hardware.goarch}) &middot; {run.goVersion} &middot; {run.method.statistic} of{' '}
              {run.method.count} runs &middot; measured {measuredOn} &middot; {them.name}{' '}
              <code className="font-mono">{them.version}</code>. Lower is faster.
            </p>
            <GlassCard className="p-0 overflow-x-auto" hover={false}>
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-fg/[0.06] text-fg-muted">
                    <th className="text-left px-4 py-3 font-medium">Query</th>
                    <th className="text-right px-4 py-3 font-medium">GoSQLX</th>
                    <th className="text-right px-4 py-3 font-medium">{them.name}</th>
                  </tr>
                </thead>
                <tbody>
                  {rows.map(({ query, gosqlx, other }) => (
                    <tr key={query.id} className="border-b border-fg/[0.04] last:border-0">
                      <td className="px-4 py-3 text-fg-muted">{query.name}</td>
                      <td className="px-4 py-3 text-right font-mono text-fg">
                        {gosqlx?.supported && gosqlx.nsPerOp !== null ? formatNs(gosqlx.nsPerOp) : 'not supported'}
                      </td>
                      <td className="px-4 py-3 text-right font-mono text-fg-muted">
                        {other?.supported && other.nsPerOp !== null ? formatNs(other.nsPerOp) : 'not supported'}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </GlassCard>
            <p className="mt-4 text-sm text-fg-muted">
              <strong className="text-fg">Read with care.</strong> {run.caveat} Results vary by query,
              so check the rows that resemble your workload.
            </p>
            <p className="mt-3 text-sm text-fg-muted">
              Full table, methodology and reproduce steps:{' '}
              <Link href="/benchmarks/#competitors" className={link}>
                competitor benchmarks
              </Link>
              . Source: <code className="font-mono">benchmarks/compare/results/latest.json</code>, commit{' '}
              <code className="font-mono">{run.commit.slice(0, 7)}</code>.
            </p>
          </div>
        </section>
      )}

      <section className="section-padding pb-10">
        <div className="container-width max-w-3xl text-sm text-fg-muted space-y-2">
          <h2 className="text-2xl font-bold text-fg mb-2">What GoSQLX offers</h2>
          <p>
            Pure Go with no CGo, {PROJECT.dialectCount} dialects, {PROJECT.lintRuleCount} built-in lint rules,
            a formatter, a SQL injection scanner, an LSP server and an MCP server. Requires {PROJECT.minGo}.
          </p>
          {page.migrationDoc && (
            <p>
              Moving over?{' '}
              <Link href={`/docs/${page.migrationDoc.slug}/`} className={link}>
                {page.migrationDoc.label}
              </Link>
              .
            </p>
          )}
          <p>
            <Link href="/compare/" className={link}>
              Full feature matrix
            </Link>
          </p>
        </div>
      </section>

      <section className="section-padding pb-24">
        <div className="container-width text-center">
          <Link href="/docs/getting-started">
            <Button>Try GoSQLX</Button>
          </Link>
        </div>
      </section>
    </div>
  );
}
