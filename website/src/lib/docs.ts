import fs from 'fs';
import path from 'path';
import matter from 'gray-matter';
import { DOCS_SIDEBAR } from './constants';

export interface Doc {
  slug: string;
  title: string;
  content: string;
  category: string;
}

export interface DocHeading {
  id: string;
  text: string;
  level: number;
}

const DOCS_DIR = path.join(process.cwd(), '..', 'docs');

function extractTitleFromMarkdown(content: string): string {
  const match = content.match(/^#\s+(.+)$/m);
  return match ? match[1].trim() : 'Untitled';
}

export function extractHeadings(content: string): DocHeading[] {
  const headings: DocHeading[] = [];
  const regex = /^(#{2,3})\s+(.+)$/gm;
  let match;
  while ((match = regex.exec(content)) !== null) {
    const text = match[2].trim();
    const id = text
      .toLowerCase()
      .replace(/[^\w\s-]/g, '')
      .replace(/\s+/g, '-');
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

export function getDocBySlug(slug: string): Doc | null {
  // Find the item in sidebar config
  let sidebarItem: { slug: string; file: string; label: string } | undefined;
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
    content,
    category: categoryName,
  };
}

/** Get adjacent docs for prev/next navigation */
export function getAdjacentDocs(slug: string): {
  prev: { slug: string; title: string } | null;
  next: { slug: string; title: string } | null;
} {
  const allItems: { slug: string; label: string }[] = [];
  for (const category of DOCS_SIDEBAR) {
    for (const item of category.items) {
      allItems.push({ slug: item.slug, label: item.label });
    }
  }

  const index = allItems.findIndex((item) => item.slug === slug);
  if (index === -1) return { prev: null, next: null };

  const prev =
    index > 0
      ? { slug: allItems[index - 1].slug, title: allItems[index - 1].label }
      : null;
  const next =
    index < allItems.length - 1
      ? { slug: allItems[index + 1].slug, title: allItems[index + 1].label }
      : null;

  return { prev, next };
}
