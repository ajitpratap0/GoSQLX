/**
 * Blog articles (issue #677): tutorials, deep dives and methodology posts
 * served under /blog/. Release notes live separately under /changelog/
 * (src/content/blog, generated from CHANGELOG.md) and are not articles.
 *
 * SERVER-ONLY: reads the filesystem and expands benchmark placeholders from
 * the competitor harness JSON.
 */
import fs from 'fs';
import path from 'path';
import matter from 'gray-matter';
import { isValidSlug } from './blog-slug';
import { expandBenchPlaceholders } from './bench-markdown';
import { SITE_URL } from './site';

export interface Article {
  slug: string;
  title: string;
  /** Hand-written meta description, 120-155 characters. */
  description: string;
  /** ISO date (YYYY-MM-DD). */
  date: string;
  /** ISO date of the last substantive edit; defaults to `date`. */
  updated: string;
  tags: string[];
  /** Markdown body with benchmark placeholders already expanded. */
  content: string;
  readingMinutes: number;
}

const ARTICLES_DIR = path.join(process.cwd(), 'src/content/articles');
const DATE_RE = /^\d{4}-\d{2}-\d{2}$/;
const DESC_MIN = 120;
const DESC_MAX = 155;

/**
 * Release-note slugs (v1-14-0) are redirected from /blog/ to /changelog/ in
 * next.config.ts, so an article must never use that shape.
 */
export const RELEASE_SLUG_RE = /^v\d+-\d+-\d+$/;

/** Site-relative URL of an article (trailing slash, matching trailingSlash: true). */
export function articleHref(slug: string): string {
  if (!isValidSlug(slug)) throw new Error('invalid article slug');
  return `/blog/${encodeURIComponent(slug)}/`;
}

export function articleUrl(slug: string): string {
  return `${SITE_URL}${articleHref(slug)}`;
}

/** Stable URL of an article's Open Graph image (served by app/og/blog/[slug]). */
export function articleOgPath(slug: string): string {
  return `/og/blog/${encodeURIComponent(slug)}/`;
}

/** Raw-markdown alternate of an article, for LLMs and cross-posting. */
export function articleMarkdownPath(slug: string): string {
  return `/blog/${encodeURIComponent(slug)}.md`;
}

function readingMinutes(markdown: string): number {
  const prose = markdown.replace(/```[\s\S]*?```/g, ' ');
  const words = prose.trim().split(/\s+/).filter(Boolean).length;
  return Math.max(1, Math.round(words / 220));
}

function requireString(data: Record<string, unknown>, key: string, file: string): string {
  const v = data[key];
  // gray-matter parses bare YYYY-MM-DD values as Date objects.
  if (v instanceof Date) return v.toISOString().slice(0, 10);
  if (typeof v !== 'string' || v.trim() === '') {
    throw new Error(`${file}: frontmatter "${key}" is required`);
  }
  return v.trim();
}

export function getArticleSlugs(): string[] {
  if (!fs.existsSync(ARTICLES_DIR)) return [];
  return fs
    .readdirSync(ARTICLES_DIR)
    .filter((f) => f.endsWith('.md'))
    .map((f) => f.replace(/\.md$/, ''))
    .filter((slug) => isValidSlug(slug) && !RELEASE_SLUG_RE.test(slug));
}

const cache = new Map<string, Article>();

export function getArticleBySlug(slug: string): Article | null {
  if (!isValidSlug(slug) || RELEASE_SLUG_RE.test(slug)) return null;
  const cached = cache.get(slug);
  if (cached) return cached;

  const file = path.join(ARTICLES_DIR, `${slug}.md`);
  if (!fs.existsSync(file)) return null;

  const { data, content } = matter(fs.readFileSync(file, 'utf-8'));
  const rel = `src/content/articles/${slug}.md`;

  const title = requireString(data, 'title', rel);
  const description = requireString(data, 'description', rel);
  const date = requireString(data, 'date', rel);
  const updated = data.updated === undefined ? date : requireString(data, 'updated', rel);
  if (!DATE_RE.test(date) || !DATE_RE.test(updated)) {
    throw new Error(`${rel}: dates must be YYYY-MM-DD`);
  }
  if (description.length < DESC_MIN || description.length > DESC_MAX) {
    throw new Error(`${rel}: description must be ${DESC_MIN}-${DESC_MAX} characters (got ${description.length})`);
  }
  const tags = Array.isArray(data.tags) ? data.tags.map(String) : [];

  const body = expandBenchPlaceholders(content.trim(), rel);
  const article: Article = {
    slug,
    title,
    description,
    date,
    updated,
    tags,
    content: body,
    readingMinutes: readingMinutes(body),
  };
  cache.set(slug, article);
  return article;
}

/** All articles, newest first (ties broken by title). */
export function getAllArticles(): Article[] {
  return getArticleSlugs()
    .map((slug) => getArticleBySlug(slug))
    .filter((a): a is Article => a !== null)
    .sort((a, b) => b.date.localeCompare(a.date) || a.title.localeCompare(b.title));
}

/**
 * An article as standalone markdown with front matter that dev.to and Medium
 * imports understand, so a cross-post always carries the gosqlx.dev canonical.
 */
export function buildArticleMarkdown(article: Article): string {
  const yamlString = (s: string) => JSON.stringify(s);
  const url = articleUrl(article.slug);
  return [
    '---',
    `title: ${yamlString(article.title)}`,
    `description: ${yamlString(article.description)}`,
    `canonical_url: ${url}`,
    `date: ${article.date}`,
    `tags: ${article.tags.slice(0, 4).join(', ')}`,
    'published: false',
    '---',
    '',
    `*Originally published at [gosqlx.dev](${url}).*`,
    '',
    absolutizeLinks(article.content),
    '',
  ].join('\n');
}

/** Make site-relative markdown links absolute so they survive cross-posting. */
function absolutizeLinks(markdown: string): string {
  return markdown.replace(/\]\((\/[^)\s]*)\)/g, (_m, p: string) => `](${SITE_URL}${p})`);
}
