'use client';

import Link from 'next/link';
import { FadeIn } from '@/components/ui/FadeIn';
import { TerminalMockup } from '@/components/ui/TerminalMockup';

const tools = [
  'parse_sql',
  'format_sql',
  'validate_sql',
  'lint_sql',
  'analyze_sql',
  'detect_injection',
  'list_dialects',
];

export function McpSection() {
  return (
    <section className="py-20 border-t border-white/[0.06]">
      <div className="max-w-3xl mx-auto px-4 text-center">
        <FadeIn>
          <h2 className="text-3xl font-bold text-white mb-4">
            AI-Ready SQL Tools
          </h2>
          <p className="text-zinc-400 mb-10 max-w-xl mx-auto">
            Connect 7 SQL tools to Claude, Cursor, or any MCP client — no installation, no API key.
          </p>
        </FadeIn>
        <FadeIn delay={0.15}>
          <TerminalMockup
            command="claude mcp add --transport http gosqlx https://mcp.gosqlx.dev/mcp"
            output="✓ Added gosqlx (7 tools available)"
          />
        </FadeIn>
        <FadeIn delay={0.25}>
          <div className="mt-6 flex flex-wrap justify-center gap-2">
            {tools.map((tool) => (
              <span
                key={tool}
                className="text-xs font-mono text-zinc-300 bg-white/[0.03] border border-white/[0.06] rounded-md px-2.5 py-1"
              >
                {tool}
              </span>
            ))}
          </div>
        </FadeIn>
        <FadeIn delay={0.35}>
          <div className="mt-8">
            <Link
              href="/docs/mcp-guide"
              className="text-sm text-accent-indigo hover:underline inline-flex items-center gap-1"
            >
              Learn more →
            </Link>
          </div>
        </FadeIn>
      </div>
    </section>
  );
}
