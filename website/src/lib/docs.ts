import fs from 'fs';
import { execFileSync } from 'child_process';
import path from 'path';
import matter from 'gray-matter';
import GithubSlugger from 'github-slugger';
import { DOCS_SIDEBAR, type DocsSidebarItem } from './constants';

export interface Doc {
  slug: string;
  title: string;
  /** Sidebar label, used for the page <title>. */
  label: string;
  /** Hand-written meta description (120-155 chars) from DOCS_SIDEBAR. */
  description: string;
  content: string;
  category: string;
  /** Last content change (ISO 8601): git commit date, mtime fallback. Used for TechArticle dateModified. */
  modifiedAt: string;
  /** Path of the source file relative to the repo root (for edit-on-GitHub links). */
  file: string;
}

export interface DocHeading {
  id: string;
  text: string;
  level: number;
}

const DOCS_DIR = path.join(process.cwd(), '..', 'docs');

let shallowClone: boolean | null = null;

function isShallowClone(): boolean {
  if (shallowClone === null) {
    try {
      shallowClone =
        execFileSync('git', ['rev-parse', '--is-shallow-repository'], {
          cwd: DOCS_DIR,
          encoding: 'utf-8',
          stdio: ['ignore', 'pipe', 'ignore'],
        }).trim() !== 'false';
    } catch {
      shallowClone = true;
    }
  }
  return shallowClone;
}

/**
 * Date the doc file last changed. Uses the git commit date, but falls back to the
 * file mtime when git history is unavailable or shallow (Vercel clones are shallow,
 * so every file would otherwise report the tip commit date).
 */
export function getLastUpdated(filePath: string): string {
  if (!isShallowClone()) {
    try {
      const out = execFileSync('git', ['log', '-1', '--format=%cI', '--', filePath], {
        cwd: DOCS_DIR,
        encoding: 'utf-8',
        stdio: ['ignore', 'pipe', 'ignore'],
      }).trim();
      if (out) return out;
    } catch {
      // fall through to mtime
    }
  }
  return fs.statSync(filePath).mtime.toISOString();
}

function extractTitleFromMarkdown(content: string): string {
  const match = content.match(/^#\s+(.+)$/m);
  return match ? match[1].trim() : 'Untitled';
}

/**
 * CommonMark: a closing fence uses the same character, is at least as long as the
 * opener, and carries no info string (so a nested ```sql line inside a ```go block is
 * content, not a closer). `m` is the match of /^ {0,3}(`{3,}|~{3,})(.*)$/.
 */
function closesFence(m: RegExpMatchArray | null, fence: string): boolean {
  return !!m && m[1][0] === fence[0] && m[1].length >= fence.length && m[2].trim() === '';
}

/** Remove fenced code blocks (``` or ~~~) so their contents are not parsed as prose. */
export function stripCodeFences(content: string): string {
  const out: string[] = [];
  let fence: string | null = null;
  for (const line of content.split('\n')) {
    const m = line.match(/^ {0,3}(`{3,}|~{3,})(.*)$/);
    if (fence === null) {
      if (m) fence = m[1];
      else out.push(line);
    } else if (closesFence(m, fence)) {
      fence = null;
    }
  }
  return out.join('\n');
}

/** Rendered text of a heading: links, backticks and emphasis markers removed (underscores in identifiers are kept). */
function renderedHeadingText(raw: string): string {
  return raw
    .replace(/\[([^\]]+)\]\([^)]*\)/g, '$1')
    .replace(/\\([_*`])/g, '$1')
    .replace(/[`*]/g, '')
    .replace(/(^|\s)_+([^_\s][^_]*?)_+(?=\s|$)/g, '$1$2')
    .trim();
}

export function extractHeadings(content: string): DocHeading[] {
  const headings: DocHeading[] = [];
  const slugger = new GithubSlugger();
  const regex = /^(#{1,6})\s+(.+)$/gm;
  let match;
  const body = stripCodeFences(content);
  while ((match = regex.exec(body)) !== null) {
    const rendered = renderedHeadingText(match[2]);
    // Slug the same text rehype-slug sees (trailing colon is dropped by the slugger)
    const id = slugger.slug(rendered);
    // Every level feeds the slugger (as rehype-slug does); only h2/h3 are listed
    if (match[1].length < 2 || match[1].length > 3) continue;
    const text = rendered.replace(/:+$/, '').trim();
    headings.push({ id, text, level: match[1].length });
  }
  return headings;
}

export function getDocSlugs(): string[] {
  const slugs: string[] = [];
  for (const category of DOCS_SIDEBAR) {
    for (const item of category.items) {
      slugs.push(item.slug);
    }
  }
  return slugs;
}

export function getAllDocs(): Doc[] {
  const docs: Doc[] = [];
  for (const category of DOCS_SIDEBAR) {
    for (const item of category.items) {
      const doc = getDocBySlug(item.slug);
      if (doc) docs.push(doc);
    }
  }
  return docs;
}

const REPO_BLOB = 'https://github.com/ajitpratap0/GoSQLX/blob/main/';
const REPO_TREE = 'https://github.com/ajitpratap0/GoSQLX/tree/main/';

let fileToSlug: Map<string, string> | null = null;

function docsFileMap(): Map<string, string> {
  if (!fileToSlug) {
    fileToSlug = new Map();
    for (const category of DOCS_SIDEBAR) {
      for (const item of category.items) fileToSlug.set(item.file, item.slug);
    }
  }
  return fileToSlug;
}

/**
 * Resolve a relative link written for GitHub (e.g. `../api/ast.md#visitor-pattern`)
 * from the doc at `fromFile` (relative to docs/). Docs pages map to their site URL;
 * anything else in the repo maps to its GitHub URL. Absolute and in-page links are
 * returned unchanged.
 */
export function resolveDocLink(href: string, fromFile: string): string {
  if (/^([a-z][a-z0-9+.-]*:|\/|#)/i.test(href)) return href;
  const hashAt = href.indexOf('#');
  const target = hashAt === -1 ? href : href.slice(0, hashAt);
  const hash = hashAt === -1 ? '' : href.slice(hashAt);
  if (!target) return href;
  const resolved = path.posix.normalize(path.posix.join(path.posix.dirname(fromFile), target));
  const repoBase = target.endsWith('/') ? REPO_TREE : REPO_BLOB;
  if (resolved.startsWith('../')) {
    // Outside docs/: link to the file in the repository.
    const repoPath = resolved.slice(3);
    return repoPath.startsWith('../') ? href : `${repoBase}${repoPath}${hash}`;
  }
  const slug = docsFileMap().get(resolved);
  if (slug) return `/docs/${slug}/${hash.toLowerCase()}`;
  return `${repoBase}docs/${resolved}${hash}`;
}

/** Rewrite relative markdown links (outside code fences) so they work on the site. */
export function rewriteDocLinks(content: string, fromFile: string): string {
  const out: string[] = [];
  let fence: string | null = null;
  for (const line of content.split('\n')) {
    const m = line.match(/^ {0,3}(`{3,}|~{3,})(.*)$/);
    if (fence === null && m) {
      fence = m[1];
      out.push(line);
      continue;
    }
    if (fence !== null) {
      if (closesFence(m, fence)) fence = null;
      out.push(line);
      continue;
    }
    out.push(
      line.replace(/\]\(([^)\s]+)(\s+"[^"]*")?\)/g, (_all, href: string, title: string | undefined) =>
        `](${resolveDocLink(href, fromFile)}${title ?? ''})`
      )
    );
  }
  return out.join('\n');
}

export function getDocBySlug(slug: string): Doc | null {
  // Find the item in sidebar config
  let sidebarItem: DocsSidebarItem | undefined;
  let categoryName = '';

  for (const category of DOCS_SIDEBAR) {
    for (const item of category.items) {
      if (item.slug === slug) {
        sidebarItem = item;
        categoryName = category.category;
        break;
      }
    }
    if (sidebarItem) break;
  }

  if (!sidebarItem) return null;

  const filePath = path.join(DOCS_DIR, sidebarItem.file);

  if (!fs.existsSync(filePath)) return null;

  const raw = fs.readFileSync(filePath, 'utf-8');
  const { data, content } = matter(raw);

  const title = data.title || extractTitleFromMarkdown(raw) || sidebarItem.label;

  return {
    slug: sidebarItem.slug,
    title,
    label: sidebarItem.label,
    description: sidebarItem.description,
    content: rewriteDocLinks(content, sidebarItem.file),
    category: categoryName,
    modifiedAt: getLastUpdated(filePath),
    file: `docs/${sidebarItem.file}`,
  };
}

export interface AdjacentDoc {
  slug: string;
  title: string;
  category: string;
}

/** Get adjacent docs for prev/next navigation (crosses category boundaries). */
export function getAdjacentDocs(slug: string): {
  prev: AdjacentDoc | null;
  next: AdjacentDoc | null;
} {
  const allItems: AdjacentDoc[] = [];
  for (const category of DOCS_SIDEBAR) {
    for (const item of category.items) {
      allItems.push({ slug: item.slug, title: item.label, category: category.category });
    }
  }

  const index = allItems.findIndex((item) => item.slug === slug);
  if (index === -1) return { prev: null, next: null };

  return {
    prev: index > 0 ? allItems[index - 1] : null,
    next: index < allItems.length - 1 ? allItems[index + 1] : null,
  };
}
