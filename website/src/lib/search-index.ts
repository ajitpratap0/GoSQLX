import { DOCS_SIDEBAR } from './constants';

export interface SearchEntry {
  slug: string;
  title: string;
  category: string;
  description: string;
  headings: string[];
}

/**
 * Build a flat array of all docs metadata for Fuse.js indexing.
 * This runs client-side on first search using the sidebar config
 * (no fs access needed).
 */
export function buildSearchIndex(): SearchEntry[] {
  const entries: SearchEntry[] = [];

  for (const group of DOCS_SIDEBAR) {
    for (const item of group.items) {
      entries.push({
        slug: item.slug,
        title: item.label,
        category: group.category,
        description: `${group.category} - ${item.label}`,
        headings: [],
      });
    }
  }

  return entries;
}
