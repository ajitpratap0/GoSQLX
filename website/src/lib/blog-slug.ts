/**
 * Blog slug validation and URL helpers.
 *
 * Kept free of Node-only imports (fs, path) so client components can use it.
 */

/**
 * Allowed blog slug shape: lowercase alphanumeric segments separated by single
 * hyphens (e.g. "v1-14-0"). Slugs come from file names on disk and flow into
 * URLs and filesystem paths, so anything outside this pattern is rejected.
 */
const SLUG_PATTERN = /^[a-z0-9]+(?:-[a-z0-9]+)*$/;
const MAX_SLUG_LENGTH = 128;

export function isValidSlug(slug: unknown): slug is string {
  return (
    typeof slug === 'string' &&
    slug.length <= MAX_SLUG_LENGTH &&
    SLUG_PATTERN.test(slug)
  );
}

/**
 * Builds the site-relative URL for a blog post. The slug is validated and
 * URI-encoded so stored data can never inject markup or a javascript: URL.
 */
export function blogPostHref(slug: string): string {
  if (!isValidSlug(slug)) {
    throw new Error('invalid blog slug');
  }
  return `/changelog/${encodeURIComponent(slug)}`;
}
