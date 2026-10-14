const REPO_API = 'https://api.github.com/repos/ajitpratap0/GoSQLX';

/**
 * Returns the repository's real stargazer count, fetched on the server and
 * revalidated hourly. Returns null when GitHub is unreachable or the response
 * is not a valid count, so callers can hide the number instead of inventing one.
 */
export async function getStars(): Promise<number | null> {
  try {
    const r = await fetch(REPO_API, {
      headers: { Accept: 'application/vnd.github+json' },
      next: { revalidate: 3600 },
    });
    if (!r.ok) return null;
    const d: unknown = await r.json();
    const count = (d as { stargazers_count?: unknown } | null)?.stargazers_count;
    return typeof count === 'number' && Number.isFinite(count) && count >= 0 ? count : null;
  } catch {
    return null;
  }
}

export function formatStars(n: number): string {
  return n >= 1000 ? `${(n / 1000).toFixed(1)}k` : String(n);
}
