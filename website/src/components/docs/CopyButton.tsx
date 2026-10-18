'use client';

import { useEffect, useRef, useState } from 'react';

type CopyState = 'idle' | 'copied' | 'failed';

const REGION_ID = 'copy-code-status';

/**
 * One polite live region per page, shared by every copy button (a docs page
 * can carry ~100 code blocks). Created on first mount so it already exists in
 * the accessibility tree before the first announcement.
 */
function statusRegion(): HTMLElement {
  const existing = document.getElementById(REGION_ID);
  if (existing) return existing;
  const region = document.createElement('div');
  region.id = REGION_ID;
  region.className = 'sr-only';
  region.setAttribute('role', 'status');
  region.setAttribute('aria-live', 'polite');
  document.body.appendChild(region);
  return region;
}

function announce(message: string) {
  const region = statusRegion();
  // Clear first so repeating the same message is announced again.
  region.textContent = '';
  window.setTimeout(() => {
    region.textContent = message;
  }, 50);
}

/**
 * Copy-to-clipboard for a code block. Copies `text` when given, otherwise the
 * text of the <pre> inside the closest [data-code-block] wrapper (so highlighted
 * markup can stay server-rendered). Visible on hover, keyboard focus and touch
 * screens; the result is announced through one shared polite live region.
 */
export function CopyButton({ text }: { text?: string }) {
  const [state, setState] = useState<CopyState>('idle');
  const ref = useRef<HTMLButtonElement>(null);
  const timer = useRef<ReturnType<typeof setTimeout> | null>(null);

  useEffect(() => {
    statusRegion();
    return () => {
      if (timer.current) clearTimeout(timer.current);
    };
  }, []);

  const flash = (next: CopyState) => {
    announce(
      next === 'copied' ? 'Code copied to clipboard' : 'Copy failed, select the code and copy it manually',
    );
    setState(next);
    if (timer.current) clearTimeout(timer.current);
    timer.current = setTimeout(() => setState('idle'), 2000);
  };

  const copy = () => {
    const value =
      text ?? ref.current?.closest('[data-code-block]')?.querySelector('pre')?.textContent ?? '';
    if (!navigator.clipboard || !value) {
      flash('failed');
      return;
    }
    navigator.clipboard.writeText(value.replace(/\n$/, '')).then(
      () => flash('copied'),
      () => flash('failed'),
    );
  };

  const label = state === 'copied' ? 'Copied' : state === 'failed' ? 'Copy failed' : 'Copy code';

  return (
    <button
      ref={ref}
      type="button"
      onClick={copy}
      aria-label={label}
      title={state === 'failed' ? 'Clipboard unavailable. Select the code and copy it manually.' : label}
      className="absolute right-2 top-2 flex h-8 w-8 items-center justify-center rounded-md border border-code-border bg-code-bg text-fg-muted opacity-0 transition-opacity hover:text-fg focus-visible:opacity-100 group-hover:opacity-100 group-focus-within:opacity-100 max-lg:h-11 max-lg:w-11 [@media(hover:none)]:opacity-100"
    >
      {state === 'copied' ? (
        <svg aria-hidden="true" className="h-4 w-4 text-ok" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
          <path strokeLinecap="round" strokeLinejoin="round" d="M5 13l4 4L19 7" />
        </svg>
      ) : state === 'failed' ? (
        <svg aria-hidden="true" className="h-4 w-4 text-danger" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
          <path strokeLinecap="round" strokeLinejoin="round" d="M6 18L18 6M6 6l12 12" />
        </svg>
      ) : (
        <svg aria-hidden="true" className="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
          <path strokeLinecap="round" strokeLinejoin="round" d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z" />
        </svg>
      )}
    </button>
  );
}
