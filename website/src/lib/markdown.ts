import { compileMDX } from 'next-mdx-remote/rsc';
import remarkGfm from 'remark-gfm';
import rehypeSlug from 'rehype-slug';
import { visit, SKIP } from 'unist-util-visit';
import type { Root as MdastRoot, Paragraph, PhrasingContent } from 'mdast';
import type { Root as HastRoot, Element, ElementContent } from 'hast';
import { mdxComponents } from '@/components/docs/mdx-components';
import { getHighlighter, resolveLang, THEME_NAME } from './highlight';

/** Plain text of an mdast node (for the line-start checks below). */
function mdText(node: PhrasingContent | undefined): string {
  if (!node) return '';
  if ('value' in node && typeof node.value === 'string') return node.value;
  if ('children' in node) return (node.children as PhrasingContent[]).map(mdText).join('');
  return '';
}

// A line that opens with an emoji/status symbol (✅ ❌ ⚠️) or a bracketed tag
// such as [DIALECT-3] / [CLI-1/2].
const ITEM_LINE = /^(?:\p{Extended_Pictographic}|\[[A-Z][A-Z0-9/_.-]*\])/u;

/** Does the line that starts at `children[next]` (right after a newline) open a one-line item? */
function siblingStartsItemLine(children: PhrasingContent[], next: number): boolean {
  const node = children[next];
  if (!node) return false;
  if (node.type === 'text') return ITEM_LINE.test(node.value.replace(/^[ \t]+/, ''));
  // "**Key**:" / "**Key:**" metadata lines (Version, Last Updated, Industry, ...).
  if (node.type === 'strong') {
    return mdText(node).trimEnd().endsWith(':') || /^:/.test(mdText(children[next + 1]));
  }
  return false;
}

/**
 * Keep line-per-item blocks on separate lines (#753) without touching
 * hard-wrapped prose. A single newline inside a paragraph becomes <br> only
 * when the next line starts with an emoji/status symbol, a bracketed tag
 * ([DIALECT-3]) or a bold "**Key**:" label: the metadata blocks
 * (**Version**: ... / **Industry:** ...), emoji checklists and the [1.9.0]
 * release notes. Every other newline stays a soft break (a space), so wrapped
 * sentences are not split mid-line.
 */
export function remarkSoftBreaks() {
  return (tree: MdastRoot) => {
    visit(tree, 'paragraph', (para: Paragraph) => {
      const children = para.children;
      const out: PhrasingContent[] = [];
      children.forEach((node, idx) => {
        if (node.type !== 'text' || !node.value.includes('\n')) {
          out.push(node);
          return;
        }
        const parts = node.value.split(/[ \t]*\r?\n/);
        let buf = parts[0];
        for (let i = 1; i < parts.length; i++) {
          const rest = parts[i].replace(/^[ \t]+/, '');
          const isLast = i === parts.length - 1;
          const item = rest ? ITEM_LINE.test(rest) : isLast && siblingStartsItemLine(children, idx + 1);
          if (item) {
            if (buf) out.push({ type: 'text', value: buf });
            out.push({ type: 'break' });
            buf = rest;
          } else {
            buf += '\n' + parts[i];
          }
        }
        if (buf) out.push({ type: 'text', value: buf });
      });
      para.children = out;
    });
  };
}

function textOf(node: ElementContent): string {
  if (node.type === 'text') return node.value;
  if (node.type === 'element') return node.children.map(textOf).join('');
  return '';
}

/**
 * Highlight fenced code blocks at build time with Shiki (#748). Output spans
 * carry `color: var(--shiki-token-*)`, which globals.css maps to design tokens
 * so one markup works in both themes.
 */
export function rehypeShikiTokens() {
  return async (tree: HastRoot) => {
    const highlighter = await getHighlighter();
    visit(tree, 'element', (node: Element) => {
      if (node.tagName !== 'pre') return;
      const code = node.children.find(
        (c): c is Element => c.type === 'element' && c.tagName === 'code',
      );
      if (!code) return SKIP;
      const classes = Array.isArray(code.properties.className) ? code.properties.className : [];
      const langClass = classes.map(String).find((c) => c.startsWith('language-'));
      const lang = resolveLang(highlighter, langClass?.slice('language-'.length));
      const source = textOf(code).replace(/\n$/, '');

      const out = highlighter.codeToHast(source, { lang, theme: THEME_NAME });
      const pre = out.children.find((c): c is Element => c.type === 'element' && c.tagName === 'pre');
      const highlighted = pre?.children.find(
        (c): c is Element => c.type === 'element' && c.tagName === 'code',
      );
      if (!highlighted) return SKIP;

      highlighted.properties = { className: [`language-${lang}`] };
      node.properties = { ...node.properties, className: ['shiki'], dataLanguage: lang };
      node.children = [highlighted];
      return SKIP;
    });
  };
}

/** Compile repo markdown (docs, blog articles, release notes) with the shared pipeline. */
export async function renderMarkdown(source: string) {
  const { content } = await compileMDX({
    source,
    options: {
      mdxOptions: {
        format: 'md',
        remarkPlugins: [remarkGfm, remarkSoftBreaks],
        rehypePlugins: [rehypeSlug, rehypeShikiTokens],
      },
    },
    components: mdxComponents,
  });
  return content;
}
