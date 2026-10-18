/**
 * Remark plugins for rendering CHANGELOG.md release sections on /changelog/<slug>/.
 *
 * Kept free of Node-only and path-alias imports so `node --test` can load this
 * file directly (see scripts/changelog.test.mjs).
 */
import type { Heading, Link, Parent, PhrasingContent, Root, Text } from 'mdast';
import { SKIP, visit } from 'unist-util-visit';

export const GITHUB_REPO_URL = 'https://github.com/ajitpratap0/GoSQLX';

/**
 * The page renders the release title as its only <h1>, and release sections in
 * CHANGELOG.md start at `###`. Re-level headings so the body starts at <h2> and
 * never skips a level (H1 -> H3 or H2 -> H4), keeping the outline accessible.
 */
export function remarkChangelogHeadings() {
  return (tree: Root) => {
    let min = 6;
    visit(tree, 'heading', (node: Heading) => {
      min = Math.min(min, node.depth);
    });
    const shift = min - 2;
    let previous = 1;
    visit(tree, 'heading', (node: Heading) => {
      const depth = Math.min(node.depth - shift, previous + 1, 6);
      node.depth = Math.max(depth, 2) as Heading['depth'];
      previous = node.depth;
    });
  };
}

/** `#123` preceded by start-of-text or a non-word character (not `&#123;`). */
const ISSUE_REF = /(^|[^\w&/#])#(\d{1,6})\b/g;

function splitText(value: string): PhrasingContent[] | null {
  const parts: PhrasingContent[] = [];
  let last = 0;
  for (const match of value.matchAll(ISSUE_REF)) {
    const start = (match.index ?? 0) + match[1].length;
    if (start > last) parts.push({ type: 'text', value: value.slice(last, start) });
    const num = match[2];
    const link: Link = {
      type: 'link',
      // GitHub redirects /issues/N to /pull/N when N is a pull request.
      url: `${GITHUB_REPO_URL}/issues/${num}`,
      children: [{ type: 'text', value: `#${num}` }],
    };
    parts.push(link);
    last = start + num.length + 1;
  }
  if (parts.length === 0) return null;
  if (last < value.length) parts.push({ type: 'text', value: value.slice(last) });
  return parts;
}

/**
 * Turn bare `#N` issue / pull request references in prose into links to the
 * GitHub repository. Text already inside a link, and inline or fenced code,
 * is left untouched.
 */
export function remarkGithubIssueRefs() {
  return (tree: Root) => {
    visit(tree, (node, index, parent: Parent | undefined) => {
      if (node.type === 'link' || node.type === 'linkReference' || node.type === 'definition') {
        return SKIP;
      }
      if (node.type !== 'text' || !parent || index === undefined) return undefined;
      const replacement = splitText((node as Text).value);
      if (!replacement) return undefined;
      parent.children.splice(index, 1, ...(replacement as Parent['children']));
      return [SKIP, index + replacement.length];
    });
  };
}
