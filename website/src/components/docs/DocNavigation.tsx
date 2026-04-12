import Link from 'next/link';

interface NavItem {
  slug: string;
  title: string;
}

interface DocNavigationProps {
  prev: NavItem | null;
  next: NavItem | null;
}

export function DocNavigation({ prev, next }: DocNavigationProps) {
  return (
    <div className="mt-16 grid grid-cols-1 gap-4 border-t border-white/5 pt-8 sm:grid-cols-2">
      {prev ? (
        <Link
          href={`/docs/${prev.slug}`}
          className="glass glass-hover group flex flex-col gap-2 rounded-xl p-5 transition-all"
        >
          <span className="text-xs font-medium uppercase tracking-wider text-zinc-500">
            Previous
          </span>
          <span className="flex items-center gap-2 text-sm font-medium text-zinc-300 transition-colors group-hover:text-white">
            <svg
              className="h-4 w-4 shrink-0 transition-transform group-hover:-translate-x-0.5"
              fill="none"
              viewBox="0 0 24 24"
              stroke="currentColor"
              strokeWidth={2}
            >
              <path strokeLinecap="round" strokeLinejoin="round" d="M11 17l-5-5m0 0l5-5m-5 5h12" />
            </svg>
            {prev.title}
          </span>
        </Link>
      ) : (
        <div />
      )}
      {next ? (
        <Link
          href={`/docs/${next.slug}`}
          className="glass glass-hover group flex flex-col items-end gap-2 rounded-xl p-5 text-right transition-all"
        >
          <span className="text-xs font-medium uppercase tracking-wider text-zinc-500">
            Next
          </span>
          <span className="flex items-center gap-2 text-sm font-medium text-zinc-300 transition-colors group-hover:text-white">
            {next.title}
            <svg
              className="h-4 w-4 shrink-0 transition-transform group-hover:translate-x-0.5"
              fill="none"
              viewBox="0 0 24 24"
              stroke="currentColor"
              strokeWidth={2}
            >
              <path strokeLinecap="round" strokeLinejoin="round" d="M13 7l5 5m0 0l-5 5m5-5H6" />
            </svg>
          </span>
        </Link>
      ) : (
        <div />
      )}
    </div>
  );
}
