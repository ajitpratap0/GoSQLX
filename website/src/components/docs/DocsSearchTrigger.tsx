'use client';

export function DocsSearchTrigger() {
  function openSearch() {
    // Dispatch Cmd+K so the Navbar's global listener opens the modal
    window.dispatchEvent(
      new KeyboardEvent('keydown', {
        key: 'k',
        metaKey: true,
        bubbles: true,
      }),
    );
  }

  return (
    <button
      type="button"
      onClick={openSearch}
      className="mx-auto mb-12 flex w-full max-w-md items-center gap-3 rounded-xl border border-white/[0.08] bg-white/[0.03] px-4 py-3 text-sm text-zinc-500 transition-colors hover:border-white/[0.12] hover:bg-white/[0.06] hover:text-zinc-400"
      aria-label="Search documentation"
    >
      <svg
        className="h-4 w-4 shrink-0"
        fill="none"
        viewBox="0 0 24 24"
        stroke="currentColor"
        strokeWidth={2}
      >
        <path
          strokeLinecap="round"
          strokeLinejoin="round"
          d="M21 21l-5.197-5.197m0 0A7.5 7.5 0 105.196 5.196a7.5 7.5 0 0010.607 10.607z"
        />
      </svg>
      <span className="flex-1 text-left">Search documentation...</span>
      <kbd className="font-mono text-[10px] text-zinc-600 border border-white/[0.08] rounded px-1.5 py-0.5 bg-white/[0.03]">
        &#8984;K
      </kbd>
    </button>
  );
}
