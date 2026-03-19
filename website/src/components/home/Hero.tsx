'use client';

import { FadeIn } from '@/components/ui/FadeIn';
import { GlassCard } from '@/components/ui/GlassCard';
import { GradientText } from '@/components/ui/GradientText';
import { VersionBadge } from '@/components/ui/VersionBadge';
import { Button } from '@/components/ui/Button';
import Link from 'next/link';

const SAMPLE_SQL = `SELECT
  u.name,
  u.email,
  COUNT(o.id) AS order_count,
  SUM(o.total) AS lifetime_value
FROM users u
LEFT JOIN orders o ON o.user_id = u.id
WHERE u.created_at > '2024-01-01'
GROUP BY u.name, u.email
HAVING COUNT(o.id) > 5
ORDER BY lifetime_value DESC
LIMIT 20;`;

const SAMPLE_AST = `{
  "type": "Query",
  "body": {
    "type": "Select",
    "projection": [
      { "type": "CompoundIdentifier", "value": "u.name" },
      { "type": "CompoundIdentifier", "value": "u.email" },
      { "type": "Function", "name": "COUNT",
        "args": ["o.id"], "alias": "order_count" },
      { "type": "Function", "name": "SUM",
        "args": ["o.total"], "alias": "lifetime_value" }
    ],
    "from": {
      "type": "Join", "join_type": "LEFT",
      "left": { "type": "Table", "name": "users", "alias": "u" },
      "right": { "type": "Table", "name": "orders", "alias": "o" }
    },
    "selection": { "type": "BinaryOp", "op": ">" },
    "group_by": ["u.name", "u.email"],
    "having": { "type": "BinaryOp", "op": ">" },
    "order_by": [{ "expr": "lifetime_value", "asc": false }],
    "limit": 20
  }
}`;

export function Hero() {
  return (
    <section className="relative min-h-screen flex items-center justify-center overflow-hidden">
      {/* Background gradient mesh */}
      <div className="absolute inset-0 pointer-events-none overflow-hidden" aria-hidden="true">
        {/* Top-right indigo glow */}
        <div
          className="absolute top-[-20%] right-[-10%] w-[60%] h-[60%]"
          style={{
            background: 'radial-gradient(circle, rgba(99,102,241,0.15) 0%, transparent 60%)',
            filter: 'blur(80px)',
          }}
        />
        {/* Bottom-left orange glow */}
        <div
          className="absolute bottom-[-10%] left-[-10%] w-[50%] h-[50%]"
          style={{
            background: 'radial-gradient(circle, rgba(249,115,22,0.08) 0%, transparent 60%)',
            filter: 'blur(60px)',
          }}
        />
        {/* Dot grid overlay */}
        <div
          className="absolute inset-0"
          style={{
            backgroundImage: 'radial-gradient(rgba(255,255,255,0.5) 1px, transparent 1px)',
            backgroundSize: '24px 24px',
            opacity: 0.05,
          }}
        />
      </div>

      {/* Content */}
      <div className="relative z-10 max-w-5xl mx-auto px-6 py-24 text-center">
        {/* Version badge */}
        <FadeIn delay={0}>
          <div className="mb-6">
            <VersionBadge version="v1.12.0 - Remote MCP Server" />
          </div>
        </FadeIn>

        {/* Headline */}
        <FadeIn delay={0.1}>
          <h1
            className="text-3xl sm:text-5xl md:text-6xl lg:text-7xl font-bold mb-6 break-words hyphens-auto w-full max-w-full px-4 sm:px-0"
            style={{ letterSpacing: '-0.03em' }}
          >
            <GradientText>Parse SQL at the speed of Go</GradientText>
          </h1>
        </FadeIn>

        {/* Subtitle */}
        <FadeIn delay={0.2}>
          <p className="text-lg md:text-xl max-w-2xl mx-auto mb-10 text-zinc-300">
            Production-ready SQL parsing with zero-copy tokenization, object pooling, and multi-dialect support
          </p>
        </FadeIn>

        {/* Buttons */}
        <FadeIn delay={0.3}>
          <div className="flex flex-wrap items-center justify-center gap-3 mb-14">
            <Button variant="primary" href="/docs/getting-started">
              Get Started
            </Button>
            <Button variant="ghost" href="/playground">
              Try Playground
            </Button>
          </div>
        </FadeIn>

        {/* Mini playground preview */}
        <FadeIn delay={0.4}>
          <div className="relative group">
            <GlassCard hover={false} className="p-0 overflow-hidden shadow-2xl shadow-indigo-500/5">
              <div className="grid md:grid-cols-2 divide-y md:divide-y-0 divide-x-0 md:divide-x divide-white/[0.06]">
                {/* SQL Input side */}
                <div className="text-left">
                  <div className="flex items-center gap-2 px-4 py-2.5 border-b border-white/[0.06]">
                    <div className="flex gap-1.5">
                      <span className="w-2.5 h-2.5 rounded-full bg-red-500/60" />
                      <span className="w-2.5 h-2.5 rounded-full bg-yellow-500/60" />
                      <span className="w-2.5 h-2.5 rounded-full bg-green-500/60" />
                    </div>
                    <span className="text-xs text-zinc-500 font-mono ml-2">query.sql</span>
                  </div>
                  <div className="relative">
                    <pre
                      tabIndex={0}
                      role="region"
                      aria-label="SQL query input"
                      className="p-4 text-[13px] leading-relaxed font-mono text-zinc-300 overflow-x-auto max-h-[320px] focus:outline-none focus:ring-2 focus:ring-accent-indigo/50"
                    >
                      <code>{SAMPLE_SQL}</code>
                    </pre>
                    <div className="absolute right-0 top-0 bottom-0 w-8 bg-gradient-to-l from-zinc-950/60 to-transparent pointer-events-none md:hidden" aria-hidden="true" />
                  </div>
                </div>

                {/* AST Output side */}
                <div className="text-left">
                  <div className="flex items-center gap-2 px-4 py-2.5 border-b border-white/[0.06]">
                    <span className="text-xs text-zinc-500 font-mono">AST Output</span>
                    <span className="ml-auto text-[10px] text-emerald-400/70 font-mono">parsed in &lt;1ms</span>
                  </div>
                  <pre
                    tabIndex={0}
                    role="region"
                    aria-label="AST output"
                    className="p-4 text-[13px] leading-relaxed font-mono text-zinc-400 overflow-x-auto max-h-[320px] focus:outline-none focus:ring-2 focus:ring-accent-indigo/50"
                  >
                    <code>{SAMPLE_AST}</code>
                  </pre>
                </div>
              </div>

              {/* Overlay CTA */}
              <Link
                href="/playground"
                className="absolute inset-0 flex items-center justify-center bg-zinc-950/0 hover:bg-zinc-950/60 transition-all duration-300 opacity-0 group-hover:opacity-100"
              >
                <span className="bg-white text-zinc-950 px-5 py-2.5 rounded-lg font-medium text-sm shadow-lg transform scale-95 group-hover:scale-100 transition-transform duration-300">
                  Try Interactive Playground
                </span>
              </Link>
            </GlassCard>
          </div>
        </FadeIn>

      </div>
    </section>
  );
}
