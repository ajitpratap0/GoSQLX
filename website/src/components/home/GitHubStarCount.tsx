'use client';

import { useState, useEffect } from 'react';

export function GitHubStarCount() {
  const [stars, setStars] = useState<string>('1.2k');

  useEffect(() => {
    const controller = new AbortController();
    fetch('https://api.github.com/repos/ajitpratap0/GoSQLX', { signal: controller.signal })
      .then((r) => r.json())
      .then((d) => {
        if (typeof d.stargazers_count === 'number') {
          setStars(
            d.stargazers_count >= 1000
              ? `${(d.stargazers_count / 1000).toFixed(1)}k`
              : String(d.stargazers_count),
          );
        }
      })
      .catch(() => {});
    return () => controller.abort();
  }, []);

  return <span>{stars}</span>;
}
