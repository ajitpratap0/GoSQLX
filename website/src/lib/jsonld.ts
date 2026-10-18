import { SITE_URL } from '@/lib/site';

export interface Crumb {
  name: string;
  /** Site-relative path with trailing slash, e.g. "/docs/". */
  path: string;
}

interface PageJsonLdInput {
  name: string;
  description: string;
  path: string;
  /** Breadcrumb trail after "Home"; the last entry is the page itself. */
  crumbs: Crumb[];
  /** Extra entities (e.g. WebApplication) appended after WebPage and BreadcrumbList. */
  extra?: Array<Record<string, unknown>>;
}

/** WebPage + BreadcrumbList (+ extras) JSON-LD for pages that have no richer markup. */
export function pageJsonLd({
  name,
  description,
  path,
  crumbs,
  extra = [],
}: PageJsonLdInput): Array<Record<string, unknown>> {
  const url = `${SITE_URL}${path}`;
  return [
    {
      '@context': 'https://schema.org',
      '@type': 'WebPage',
      '@id': `${url}#webpage`,
      url,
      name,
      description,
      inLanguage: 'en',
      isPartOf: { '@type': 'WebSite', '@id': `${SITE_URL}/#website`, url: `${SITE_URL}/`, name: 'GoSQLX' },
    },
    {
      '@context': 'https://schema.org',
      '@type': 'BreadcrumbList',
      itemListElement: [
        { '@type': 'ListItem', position: 1, name: 'Home', item: `${SITE_URL}/` },
        ...crumbs.map((c, i) => ({
          '@type': 'ListItem',
          position: i + 2,
          name: c.name,
          item: `${SITE_URL}${c.path}`,
        })),
      ],
    },
    ...extra,
  ];
}
