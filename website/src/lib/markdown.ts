import { compileMDX } from 'next-mdx-remote/rsc';
import remarkGfm from 'remark-gfm';
import rehypeSlug from 'rehype-slug';
import { visit, SKIP } from 'unist-util-visit';
import type { Root as MdastRoot, PhrasingContent, Text } from 'mdast';
import type { Root as HastRoot, Element, ElementContent } from 'hast';
import { mdxComponents } from '@/components/docs/mdx-components';
import { getHighlighter, resolveLang, THEME_NAME } from './highlight';

/**
 * Single line breaks inside a paragraph become <br>. The docs and CHANGELOG.md
 * use one line per item for metadata blocks (**Version**: ... / **Last Updated**:
 * ...), emoji checklists and release-note entries; CommonMark would join those
 * into one run-on paragraph (#753). Same behaviour as remark-breaks.
 */
export function remarkSoftBreaks() {
  return (tree: MdastRoot) => {
    visit(tree, 'text', (node: Text, index, parent) => {
      if (!parent || index === undefined || !node.value.includes('\n')) return;
      const parts = node.value.split(/[ \t]*\r?\n[ \t]*/);
      const replacement: PhrasingContent[] = [];
      parts.forEach((value, i) => {
        if (i > 0) replacement.push({ type: 'break' });
        if (value) replacement.push({ type: 'text', value });
      });
      (parent.children as PhrasingContent[]).splice(index, 1, ...replacement);
      return [SKIP, index + replacement.length];
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
