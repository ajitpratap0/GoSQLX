import { DOCS_SIDEBAR } from '@/lib/constants';
import { extractHeadings, getDocBySlug } from '@/lib/docs';
import type { SearchEntry } from '@/lib/search-index';

// Generated once at build time; fetched lazily by the search modal.
export const dynamic = 'force-static';

export function GET() {
  const entries: SearchEntry[] = [];

  for (const group of DOCS_SIDEBAR) {
    for (const item of group.items) {
      const base = {
        slug: item.slug,
        title: item.label,
        category: group.category,
        description: item.description,
      };
      entries.push(base);

      const doc = getDocBySlug(item.slug);
      if (!doc) continue;
      for (const h of extractHeadings(doc.content)) {
        entries.push({ slug: base.slug, title: base.title, category: base.category, heading: h.text, anchor: h.id });
      }
    }
  }

  return Response.json(entries);
}
