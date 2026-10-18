import type { ReactNode } from 'react';
import { CopyButton } from '@/components/docs/CopyButton';
import { getHighlighter, resolveLang, THEME_NAME } from '@/lib/highlight';

/**
 * The one code-block frame used by docs, blog, release notes and marketing
 * pages: `.code-block` (globals.css) gives the shared --code-bg / --code-border
 * surface in both themes, plus a copy button.
 */
export function CodeBlock({ children, className = '' }: { children: ReactNode; className?: string }) {
  return (
    <div data-code-block="" className={`code-block group relative ${className}`}>
      {children}
      {/* Mobile scroll hint: right-edge fade, hidden on md+ where the scrollbar shows. */}
      <div
        aria-hidden="true"
        className="pointer-events-none absolute inset-y-px right-px w-8 rounded-r-lg bg-gradient-to-l from-code-bg to-transparent md:hidden"
      />
      <CopyButton />
    </div>
  );
}

/** Build-time highlighted snippet (server component) inside the shared CodeBlock frame. */
export async function HighlightedCode({ code, lang, label }: { code: string; lang: string; label?: string }) {
  const highlighter = await getHighlighter();
  const resolved = resolveLang(highlighter, lang);
  const html = highlighter.codeToHtml(code.replace(/\n$/, ''), {
    lang: resolved,
    theme: THEME_NAME,
    transformers: [
      {
        pre(node) {
          node.properties = {
            className: ['shiki'],
            'data-language': resolved,
            tabindex: '0',
            ...(label ? { role: 'region', 'aria-label': label } : {}),
          };
        },
        code(node) {
          node.properties = { className: [`language-${resolved}`] };
        },
      },
    ],
  });
  // Shiki escapes all source text; the markup is generated at build time from repo constants.
  return (
    <CodeBlock>
      <div className="contents" dangerouslySetInnerHTML={{ __html: html }} />
    </CodeBlock>
  );
}
