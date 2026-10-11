import fs from 'fs';
import path from 'path';
import matter from 'gray-matter';
import { isValidSlug } from './blog-slug';

export { isValidSlug, blogPostHref } from './blog-slug';

export interface BlogPost {
  slug: string;
  title: string;
  date: string;
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

export function getPostBySlug(slug: string): BlogPost | null {
  if (!isValidSlug(slug)) return null;
  const filePath = path.join(BLOG_DIR, `${slug}.md`);
  if (!fs.existsSync(filePath)) return null;

  const raw = fs.readFileSync(filePath, 'utf-8');
  const { data, content } = matter(raw);

  return {
    slug,
    title: data.title ?? '',
    date: data.date ?? '',
    version: data.version ?? '',
    description: data.description ?? '',
    content,
  };
}

export function getAllPosts(): BlogPost[] {
  return getPostSlugs()
    .map((slug) => getPostBySlug(slug))
    .filter((post): post is BlogPost => post !== null)
    .sort((a, b) => {
      // Sort by date descending, then by version descending as tiebreaker
      if (a.date && b.date && a.date !== b.date) {
        return b.date.localeCompare(a.date);
      }
      // Compare semantic versions as tiebreaker
      return compareVersions(b.version, a.version);
    });
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
