'use client';

import { useState, useEffect, useRef, useCallback, useMemo } from 'react';
import { useRouter } from 'next/navigation';
import { motion, AnimatePresence } from 'motion/react';
import Fuse from 'fuse.js';
import { buildSearchIndex, type SearchEntry } from '@/lib/search-index';

interface SearchModalProps {
  open: boolean;
  onClose: () => void;
}

export function SearchModal({ open, onClose }: SearchModalProps) {
  const [query, setQuery] = useState('');
  const [selectedIndex, setSelectedIndex] = useState(0);
  const inputRef = useRef<HTMLInputElement>(null);
  const overlayRef = useRef<HTMLDivElement>(null);
  const listRef = useRef<HTMLUListElement>(null);
  const router = useRouter();

  const index = useMemo(() => buildSearchIndex(), []);

  const fuse = useMemo(
    () =>
      new Fuse(index, {
        keys: [
          { name: 'title', weight: 0.5 },
          { name: 'category', weight: 0.3 },
          { name: 'description', weight: 0.2 },
        ],
        threshold: 0.4,
        includeMatches: true,
      }),
    [index],
  );

  const results = useMemo(() => {
    if (!query.trim()) return index.slice(0, 10);
    return fuse.search(query, { limit: 10 }).map((r) => r.item);
  }, [query, fuse, index]);

  // Reset state when modal opens
  useEffect(() => {
    if (open) {
      setQuery('');
      setSelectedIndex(0);
      // Small delay so the DOM is painted before we focus
      requestAnimationFrame(() => inputRef.current?.focus());
    }
  }, [open]);

  // Scroll selected item into view
  useEffect(() => {
    if (!listRef.current) return;
    const selected = listRef.current.children[selectedIndex] as HTMLElement | undefined;
    selected?.scrollIntoView({ block: 'nearest' });
  }, [selectedIndex]);

  const navigate = useCallback(
    (entry: SearchEntry) => {
      onClose();
      router.push(`/docs/${entry.slug}`);
    },
    [onClose, router],
  );

  const handleKeyDown = useCallback(
    (e: React.KeyboardEvent) => {
      switch (e.key) {
        case 'ArrowDown':
          e.preventDefault();
          setSelectedIndex((i) => (i + 1) % results.length);
          break;
        case 'ArrowUp':
          e.preventDefault();
          setSelectedIndex((i) => (i - 1 + results.length) % results.length);
          break;
        case 'Enter':
          e.preventDefault();
          if (results[selectedIndex]) navigate(results[selectedIndex]);
          break;
        case 'Escape':
          e.preventDefault();
          onClose();
          break;
      }
    },
    [results, selectedIndex, navigate, onClose],
  );

  // Reset selection when results change
  useEffect(() => {
    setSelectedIndex(0);
  }, [results]);

  return (
    <AnimatePresence>
    {open && (
    <div
      ref={overlayRef}
      className="fixed inset-0 z-[100] flex items-start justify-center pt-[min(20vh,10rem)] px-4"
      onClick={(e) => {
        if (e.target === overlayRef.current) onClose();
      }}
      role="dialog"
      aria-modal="true"
      aria-label="Search documentation"
    >
      {/* Backdrop */}
      <motion.div
        className="fixed inset-0 bg-black/60 backdrop-blur-sm"
        aria-hidden="true"
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        exit={{ opacity: 0 }}
        transition={{ duration: 0.15 }}
      />

      {/* Modal */}
      <motion.div
        className="relative w-full max-w-lg glass overflow-hidden shadow-2xl shadow-black/40"
        initial={{ opacity: 0, scale: 0.95, y: 10 }}
        animate={{ opacity: 1, scale: 1, y: 0 }}
        exit={{ opacity: 0, scale: 0.95, y: 10 }}
        transition={{ duration: 0.2, ease: [0.25, 0.1, 0.25, 1] }}
      >
        {/* Search input */}
        <div className="flex items-center gap-3 border-b border-white/[0.08] px-4">
          <svg
            className="h-4 w-4 shrink-0 text-zinc-500"
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
          <input
            ref={inputRef}
            type="text"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            onKeyDown={handleKeyDown}
            placeholder="Search documentation..."
            className="flex-1 bg-transparent py-3.5 text-sm text-white placeholder:text-zinc-500 outline-none"
            aria-label="Search documentation"
            autoComplete="off"
            spellCheck={false}
          />
          <kbd className="hidden sm:inline-flex items-center gap-0.5 rounded border border-white/[0.1] bg-white/[0.04] px-1.5 py-0.5 font-mono text-[10px] text-zinc-500">
            ESC
          </kbd>
        </div>

        {/* Results */}
        <ul
          ref={listRef}
          className="max-h-[min(50vh,24rem)] overflow-y-auto py-2"
          role="listbox"
          aria-label="Search results"
        >
          {results.length === 0 && (
            <li className="px-4 py-8 text-center text-sm text-zinc-500">
              No results found for &ldquo;{query}&rdquo;
            </li>
          )}
          {results.map((entry, i) => (
            <li
              key={entry.slug}
              role="option"
              aria-selected={i === selectedIndex}
              className={`mx-2 flex cursor-pointer items-center gap-3 rounded-lg px-3 py-2.5 text-sm transition-colors ${
                i === selectedIndex
                  ? 'bg-accent-indigo/20 text-white'
                  : 'text-zinc-400 hover:bg-white/[0.04] hover:text-zinc-200'
              }`}
              onClick={() => navigate(entry)}
              onMouseEnter={() => setSelectedIndex(i)}
            >
              {/* Icon */}
              <svg
                className="h-4 w-4 shrink-0 text-zinc-600"
                fill="none"
                viewBox="0 0 24 24"
                stroke="currentColor"
                strokeWidth={1.5}
              >
                <path
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  d="M19.5 14.25v-2.625a3.375 3.375 0 00-3.375-3.375h-1.5A1.125 1.125 0 0113.5 7.125v-1.5a3.375 3.375 0 00-3.375-3.375H8.25m2.25 0H5.625c-.621 0-1.125.504-1.125 1.125v17.25c0 .621.504 1.125 1.125 1.125h12.75c.621 0 1.125-.504 1.125-1.125V11.25a9 9 0 00-9-9z"
                />
              </svg>
              <div className="min-w-0 flex-1">
                <div className="truncate font-medium">{entry.title}</div>
                <div className="truncate text-xs text-zinc-600">{entry.category}</div>
              </div>
              {i === selectedIndex && (
                <kbd className="hidden sm:inline-flex shrink-0 items-center rounded border border-white/[0.1] bg-white/[0.04] px-1.5 py-0.5 font-mono text-[10px] text-zinc-500">
                  Enter
                </kbd>
              )}
            </li>
          ))}
        </ul>

        {/* Footer */}
        <div className="flex items-center gap-4 border-t border-white/[0.08] px-4 py-2 text-[10px] text-zinc-600">
          <span className="inline-flex items-center gap-1">
            <kbd className="rounded border border-white/[0.08] bg-white/[0.03] px-1 py-0.5 font-mono">&uarr;&darr;</kbd>
            navigate
          </span>
          <span className="inline-flex items-center gap-1">
            <kbd className="rounded border border-white/[0.08] bg-white/[0.03] px-1 py-0.5 font-mono">Enter</kbd>
            open
          </span>
          <span className="inline-flex items-center gap-1">
            <kbd className="rounded border border-white/[0.08] bg-white/[0.03] px-1 py-0.5 font-mono">Esc</kbd>
            close
          </span>
        </div>
      </motion.div>
    </div>
    )}
    </AnimatePresence>
  );
}

/**
 * Hook that manages Cmd+K / Ctrl+K global shortcut for opening search.
 */
export function useSearchShortcut() {
  const [open, setOpen] = useState(false);

  useEffect(() => {
    function handleKeyDown(e: KeyboardEvent) {
      if ((e.metaKey || e.ctrlKey) && e.key === 'k') {
        e.preventDefault();
        setOpen((prev) => !prev);
      }
    }
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, []);

  return { open, setOpen };
}
