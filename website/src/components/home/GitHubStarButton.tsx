'use client';

import { useState, useEffect } from 'react';

export function GitHubStarButton() {
  const [stars, setStars] = useState<number | null>(null);

  useEffect(() => {
    const controller = new AbortController();
    fetch('https://api.github.com/repos/ajitpratap0/GoSQLX', { signal: controller.signal })
      .then((r) => r.json())
      .then((d) => { if (typeof d.stargazers_count === 'number') setStars(d.stargazers_count); })
      .catch(() => {});
    return () => controller.abort();
  }, []);

  return (
    <a
      href="https://github.com/ajitpratap0/GoSQLX"
      target="_blank"
      rel="noopener noreferrer"
      className="inline-flex items-center gap-2 px-4 py-2.5 rounded-lg border border-white/10 bg-white/5 hover:bg-white/10 transition-colors text-sm font-medium text-zinc-200"
    >
      <svg width="16" height="16" viewBox="0 0 16 16" fill="currentColor" aria-hidden="true">
        <path d="M8 .25a7.75 7.75 0 1 0 0 15.5A7.75 7.75 0 0 0 8 .25ZM6.5 13.5v-2.1a2.9 2.9 0 0 1-.8.1c-.6 0-1-.3-1.2-.8-.2-.4-.5-.8-.9-.9l-.1-.1c-.1-.1-.1-.2 0-.2l.1-.1c.5-.2.9.1 1.2.6.2.4.5.6.8.6.3 0 .5-.1.7-.2.1-.6.4-1 .8-1.3-2-.2-3.3-1-3.3-3.1 0-.7.3-1.4.7-1.9-.1-.3-.3-1 0-2 0 0 .6-.2 2 .7a6.8 6.8 0 0 1 3.6 0c1.4-.9 2-.7 2-.7.3 1 .1 1.7 0 2 .4.5.7 1.2.7 1.9 0 2.1-1.3 2.9-3.3 3.1.4.4.7 1 .7 1.9v2.5c0 .1 0 .2.1.2C10.7 14.9 12.5 12 12.5 8A4.5 4.5 0 0 0 8 3.5" />
      </svg>
      <svg width="14" height="14" viewBox="0 0 16 16" fill="currentColor" aria-hidden="true" className="text-yellow-400">
        <path d="M8 .25a.75.75 0 0 1 .673.418l1.882 3.815 4.21.612a.75.75 0 0 1 .416 1.279l-3.046 2.97.719 4.192a.751.751 0 0 1-1.088.791L8 11.347l-3.766 1.98a.75.75 0 0 1-1.088-.79l.72-4.194L.818 6.374a.75.75 0 0 1 .416-1.28l4.21-.611L7.327.668A.75.75 0 0 1 8 .25Z" />
      </svg>
      Star
      {stars !== null && (
        <span className="bg-white/10 text-zinc-300 text-xs px-1.5 py-0.5 rounded font-mono">
          {stars >= 1000 ? `${(stars / 1000).toFixed(1)}k` : stars}
        </span>
      )}
    </a>
  );
}
