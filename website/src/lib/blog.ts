import fs from 'fs';
import path from 'path';
import matter from 'gray-matter';
import { isValidSlug } from './blog-slug';

export { isValidSlug, blogPostHref } from './blog-slug';

export interface BlogPost {
  slug: string;
  title: string;
  date: string;
  /** Optional frontmatter `updated` date; falls back to `date`. */
  updated: string;
  version: string;
  description: string;
  content: string;
}

const BLOG_DIR = path.join(process.cwd(), 'src/content/blog');

export function getPostSlugs(): string[] {
  if (!fs.existsSync(BLOG_DIR)) return [];
  return fs
    .readdirSync(BLOG_DIR)
    .filter((f) => f.endsWith('.md'))
    .map((f) => f.replace(/\.md$/, ''))
    .filter(isValidSlug);
}

const DESC_MIN = 120;
const DESC_MAX = 155;

/** Strip markdown, PR references and extra whitespace from a snippet of release-note text. */
function cleanSnippet(text: string): string {
  return text
    .replace(/\[([^\]]+)\]\([^)]*\)/g, '$1')
    .replace(/[`*]/g, '')
    .replace(/\s*\((?:closes |fixes |PR )?#\d+(?:,\s*#\d+)*\)/gi, '')
    .replace(/\s+/g, ' ')
    .trim();
}

/** Pull release-note items from a section: bullets, else #### headings. */
function sectionItems(section: string): string[] {
  const items: string[] = [];
  for (const m of section.matchAll(/^[-*] ((?:.+)(?:\n {2,}\S.*)*)/gm)) {
    const raw = m[1];
    const lead = raw.match(/^\*\*(.+?)\*\*/);
    const item = cleanSnippet(lead ? lead[1] : raw).replace(/[:.]$/, '');
    if (item) items.push(item);
  }
  if (items.length === 0) {
    for (const m of section.matchAll(/^####\s+(.+)$/gm)) {
      const item = cleanSnippet(m[1]);
      if (item) items.push(item);
    }
  }
  return items;
}

/**
 * Derive a 120-155 character meta description from the post body: the first
 * `### Added` bullets (falling back to the first section that has items).
 * The version prefix keeps every description unique.
 */
export function deriveDescription(version: string, content: string): string {
  const sections = content.split(/^### (?!#)/m).slice(1);
  const added = sections.find((sec) => /^Added\b/.test(sec));
  const items = [added, ...sections.filter((sec) => sec !== added)]
    .filter((sec): sec is string => sec !== undefined)
    .flatMap(sectionItems);

  const prefix = `GoSQLX v${version} release notes: `;
  const budget = DESC_MAX - prefix.length - 1; // room for the closing period
  let body = '';
  for (const item of items) {
    const next = body ? `${body}; ${item}` : item;
    if (next.length <= budget) {
      body = next;
      if (prefix.length + body.length + 1 >= DESC_MIN) break;
    } else if (!body) {
      body = `${item.slice(0, budget - 1).replace(/\s+\S*$/, '').replace(/[,;:]$/, '')}…`;
      break;
    }
  }

  let out = body ? `${prefix}${body}.` : `${prefix}new features, fixes and improvements.`;
  const pads = [
    ' Highlights, fixes and upgrade notes for this version.',
    ' See the full release notes.',
  ];
  for (const pad of pads) {
    if (out.length >= DESC_MIN) break;
    if (out.length + pad.length <= DESC_MAX) out += pad;
  }
  return out;
}

export function getPostBySlug(slug: string): BlogPost | null {
  if (!isValidSlug(slug)) return null;
  const filePath = path.join(BLOG_DIR, `${slug}.md`);
  if (!fs.existsSync(filePath)) return null;

  const raw = fs.readFileSync(filePath, 'utf-8');
  const { data, content } = matter(raw);

  const version = String(data.version ?? '');

  return {
    slug,
    title: data.title ?? '',
    date: data.date ?? '',
    updated: data.updated ?? data.date ?? '',
    version,
    // Frontmatter `description` is unreliable (table rows, stubs), so derive it.
    description: deriveDescription(version, content),
    content,
  };
}

export function getAllPosts(): BlogPost[] {
  return getPostSlugs()
    .map((slug) => getPostBySlug(slug))
    .filter((post): post is BlogPost => post !== null)
    // Newest version first. Sorting by version rather than date keeps the
    // index in release order even where CHANGELOG.md dates are inconsistent
    // (e.g. 1.1.0 is dated before 1.0.2).
    .sort((a, b) => compareVersions(b.version, a.version));
}

function compareVersions(a: string, b: string): number {
  const pa = a.split('.').map(Number);
  const pb = b.split('.').map(Number);
  for (let i = 0; i < 3; i++) {
    const diff = (pa[i] ?? 0) - (pb[i] ?? 0);
    if (diff !== 0) return diff;
  }
  return 0;
}
