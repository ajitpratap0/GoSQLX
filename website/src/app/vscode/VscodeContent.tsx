'use client';

import { FadeIn } from '@/components/ui/FadeIn';
import { GlassCard } from '@/components/ui/GlassCard';
import { Button } from '@/components/ui/Button';
import { TerminalMockup } from '@/components/ui/TerminalMockup';

const features = [
  {
    title: 'Real-time Diagnostics',
    description: 'Instant SQL error detection as you type, with precise position information and actionable messages.',
  },
  {
    title: 'SQL Formatting',
    description: 'Auto-format SQL files on save or on demand. Consistent, readable output every time.',
  },
  {
    title: 'Linting L001\u2013L010',
    description: '10 built-in lint rules covering SELECT *, missing WHERE on UPDATE/DELETE, implicit joins, and more.',
  },
  {
    title: 'Multi-dialect',
    description: 'Supports PostgreSQL, MySQL, SQLite, SQL Server, Oracle, and Snowflake out of the box.',
  },
  {
    title: 'Bundled Binary',
    description: 'Ships with the GoSQLX binary for your platform. No external dependencies required.',
  },
  {
    title: 'LSP-powered',
    description: 'Full Language Server Protocol integration for hover info, diagnostics, and formatting.',
  },
];

export function VscodeContent() {
  return (
    <div className="min-h-screen">
      {/* Hero */}
      <section className="section-padding pt-24 pb-16 text-center">
        <div className="container-width">
          <FadeIn>
            <h1 className="text-3xl sm:text-4xl md:text-5xl lg:text-6xl font-bold tracking-tight text-white">
              GoSQLX for VS Code
            </h1>
            <p className="mt-4 text-lg text-zinc-400 max-w-2xl mx-auto">
              Real-time SQL validation, formatting, and linting directly in your editor.
              Powered by the GoSQLX parser with multi-dialect support.
            </p>
            <div className="mt-8">
              <Button
                variant="primary"
                href="https://marketplace.visualstudio.com/items?itemName=ajitpratap0.gosqlx"
                external
                aria-label="Install Extension (opens in new tab)"
              >
                Install Extension
              </Button>
            </div>
          </FadeIn>
        </div>
      </section>

      {/* Feature Grid */}
      <section className="section-padding pb-16" aria-label="Features">
        <div className="container-width">
          <h2 className="sr-only">Features</h2>
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-6">
            {features.map((f, i) => (
              <FadeIn key={f.title} delay={i * 0.08}>
                <GlassCard className="p-6 h-full">
                  <h3 className="text-lg font-semibold text-white">{f.title}</h3>
                  <p className="mt-2 text-sm text-zinc-400">{f.description}</p>
                </GlassCard>
              </FadeIn>
            ))}
          </div>
        </div>
      </section>

      {/* Install via CLI */}
      <section className="section-padding pb-16">
        <div className="container-width max-w-2xl mx-auto">
          <FadeIn>
            <h2 className="text-2xl font-bold text-white mb-6 text-center">
              Install via CLI
            </h2>
            <TerminalMockup command="code --install-extension ajitpratap0.gosqlx" />
          </FadeIn>
        </div>
      </section>

      {/* Key Settings */}
      <section className="section-padding pb-24">
        <div className="container-width max-w-2xl mx-auto">
          <FadeIn>
            <h2 className="text-2xl font-bold text-white mb-6 text-center">
              Key Settings
            </h2>
            <GlassCard className="p-6" hover={false}>
              <pre
                role="region"
                aria-label="Key Settings JSON"
                tabIndex={0}
                className="font-mono text-sm text-zinc-300 whitespace-pre overflow-x-auto"
              >
{`{
  "gosqlx.executablePath": "/usr/local/bin/gosqlx",
  "gosqlx.forcePathLookup": false
}`}
              </pre>
            </GlassCard>
          </FadeIn>
        </div>
      </section>
    </div>
  );
}
