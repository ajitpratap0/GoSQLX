export interface SearchEntry {
  slug: string;
  /** Doc (sidebar) title. */
  title: string;
  category: string;
  /** Page-level entries only; omitted on heading entries to keep the index small. */
  description?: string;
  /** Section heading this entry points at; absent for the page-level entry. */
  heading?: string;
  /** Anchor id of `heading`, for deep links. */
  anchor?: string;
}

/** URL of the build-time generated search index (see app/docs/search-index.json/route.ts). */
export const SEARCH_INDEX_URL = '/docs/search-index.json';

/** Deep link for a search entry. */
export function searchEntryHref(entry: SearchEntry): string {
  return `/docs/${entry.slug}/${entry.anchor ? `#${entry.anchor}` : ''}`;
}
