import Link from 'next/link';
import { FadeIn } from '@/components/ui/FadeIn';
import { TerminalMockup } from '@/components/ui/TerminalMockup';
import { Button } from '@/components/ui/Button';
import { PROJECT } from '@/data/metrics';

const MCP_TOOLS = [
  'parse_sql',
  'format_sql',
  'validate_sql',
  'lint_sql',
  'analyze_sql',
  'detect_injection',
  'list_dialects',
];

const EDITORS = [
  { name: 'Neovim', href: '/docs/editors/neovim/' },
  { name: 'JetBrains', href: '/docs/editors/jetbrains/' },
  { name: 'Any LSP editor', href: '/docs/lsp-guide/' },
];

/** "Use it everywhere": the MCP server for AI assistants and the language server for editors. */
export function UseEverywhere() {
  return (
    <section aria-labelledby="everywhere-heading" className="py-20 border-t border-white/[0.06]">
      <div className="max-w-6xl mx-auto px-4">
        <FadeIn viewport>
          <h2 id="everywhere-heading" className="text-3xl font-bold text-white text-center mb-4">
            Use it everywhere
          </h2>
          <p className="text-zinc-300 text-center mb-12 max-w-2xl mx-auto">
            The same parser powers your Go code, your AI assistant and your editor.
          </p>
        </FadeIn>

        <div className="grid gap-6 md:grid-cols-2">
          {/* AI assistants (MCP) */}
          <FadeIn viewport className="h-full">
            <div className="glass h-full p-6 flex flex-col">
              <h3 className="text-xl font-semibold text-white mb-2">AI assistants</h3>
              <p className="text-sm text-zinc-300 mb-5">
                Connect {PROJECT.mcpToolCount} SQL tools to Claude, Cursor or any MCP client. No installation, no API key.
              </p>
              <TerminalMockup
                command="claude mcp add --transport http gosqlx https://mcp.gosqlx.dev/mcp"
                output={`Added gosqlx (${PROJECT.mcpToolCount} tools available)`}
              />
              <ul className="mt-4 flex flex-wrap gap-2" aria-label="MCP tools">
                {MCP_TOOLS.map((tool) => (
                  <li
                    key={tool}
                    className="text-xs font-mono text-zinc-300 bg-white/[0.03] border border-white/[0.06] rounded-md px-2.5 py-1"
                  >
                    {tool}
                  </li>
                ))}
              </ul>
              <Link
                href="/docs/mcp-guide/"
                className="mt-auto pt-6 text-sm text-accent hover:underline inline-flex min-h-11 items-center gap-1"
              >
                MCP guide <span aria-hidden="true">→</span>
              </Link>
            </div>
          </FadeIn>

          {/* Editors (LSP) */}
          <FadeIn viewport delay={0.1} className="h-full">
            <div className="glass h-full p-6 flex flex-col">
              <h3 className="text-xl font-semibold text-white mb-2">Editors</h3>
              <p className="text-sm text-zinc-300 mb-5">
                Real-time validation, formatting and linting as you type, across all {PROJECT.dialectCount} dialects,
                through the built-in language server (<code className="text-xs">gosqlx lsp</code>).
              </p>
              <div className="flex flex-wrap items-center gap-3">
                <Button
                  href="https://marketplace.visualstudio.com/items?itemName=ajitpratap0.gosqlx"
                  variant="primary"
                  external
                >
                  Install for VS Code
                </Button>
                <Button href="/vscode/" variant="ghost">
                  Extension details
                </Button>
              </div>
              <ul className="mt-6 space-y-1">
                {EDITORS.map((e) => (
                  <li key={e.name}>
                    <Link
                      href={e.href}
                      className="text-sm text-accent hover:underline inline-flex min-h-11 items-center gap-1"
                    >
                      {e.name} setup <span aria-hidden="true">→</span>
                    </Link>
                  </li>
                ))}
              </ul>
            </div>
          </FadeIn>
        </div>
      </div>
    </section>
  );
}
