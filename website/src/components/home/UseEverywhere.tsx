import Link from 'next/link';
import { FadeIn } from '@/components/ui/FadeIn';
import { ReproduceSnippet } from '@/components/home/ReproduceSnippet';
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

const MCP_ADD_COMMAND = 'claude mcp add --transport http gosqlx https://mcp.gosqlx.dev/mcp';
const CLI_INSTALL_COMMAND = 'go install github.com/ajitpratap0/GoSQLX/cmd/gosqlx@latest';

const EDITORS = [
  { name: 'Neovim', href: '/docs/integrations/neovim/' },
  { name: 'JetBrains', href: '/docs/integrations/jetbrains/' },
  { name: 'Any LSP editor', href: '/docs/integrations/lsp/' },
];

/** "Use it everywhere": the MCP server for AI assistants and the language server for editors. */
export function UseEverywhere() {
  return (
    <section aria-labelledby="everywhere-heading" className="py-20 border-t border-fg/[0.06]">
      <div className="max-w-6xl mx-auto px-4">
        <FadeIn viewport>
          <h2 id="everywhere-heading" className="text-3xl font-bold text-fg text-center mb-4">
            Use it everywhere
          </h2>
          <p className="text-fg-muted text-center mb-12 max-w-2xl mx-auto">
            The same parser powers your Go code, your AI assistant and your editor.
          </p>
        </FadeIn>

        <div className="grid gap-6 md:grid-cols-2">
          {/* AI assistants (MCP) */}
          <FadeIn viewport className="h-full">
            <div className="glass h-full p-6 flex flex-col">
              <h3 className="text-xl font-semibold text-fg mb-2">AI assistants</h3>
              <p className="text-sm text-fg-muted mb-5">
                Connect {PROJECT.mcpToolCount} SQL tools to Claude, Cursor or any MCP client. No installation, no API key.
              </p>
              <ReproduceSnippet command={MCP_ADD_COMMAND} what="MCP install command" />
              <p className="mt-2 font-mono text-xs text-fg-subtle">
                {PROJECT.mcpToolCount} tools: see the list below
              </p>
              <ul className="mt-4 flex flex-wrap gap-2" aria-label="MCP tools">
                {MCP_TOOLS.map((tool) => (
                  <li
                    key={tool}
                    className="text-xs font-mono text-fg-muted bg-fg/[0.03] border border-fg/[0.06] rounded-md px-2.5 py-1"
                  >
                    {tool}
                  </li>
                ))}
              </ul>
              <Link
                href="/docs/integrations/mcp/"
                className="mt-auto pt-6 text-sm text-accent hover:underline inline-flex min-h-11 items-center gap-1"
              >
                MCP guide <span aria-hidden="true">→</span>
              </Link>
            </div>
          </FadeIn>

          {/* Editors (LSP) */}
          <FadeIn viewport delay={0.1} className="h-full">
            <div className="glass h-full p-6 flex flex-col">
              <h3 className="text-xl font-semibold text-fg mb-2">Editors</h3>
              <p className="text-sm text-fg-muted mb-5">
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
              <div className="mt-5">
                <ReproduceSnippet command={CLI_INSTALL_COMMAND} what="CLI install command" />
              </div>
              <ul className="mt-4 space-y-1">
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
