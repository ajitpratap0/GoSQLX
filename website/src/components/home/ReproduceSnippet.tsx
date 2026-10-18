'use client';

import { useEffect, useRef, useState } from 'react';

type CopyState = 'idle' | 'copied' | 'failed';

/** A shell command with an always-visible copy button (keyboard and touch friendly). */
export function ReproduceSnippet({ command, what = 'benchmark command', prompt = true }: { command: string; what?: string; prompt?: boolean }) {
  const [state, setState] = useState<CopyState>('idle');
  const timer = useRef<ReturnType<typeof setTimeout> | null>(null);

  useEffect(() => () => {
    if (timer.current) clearTimeout(timer.current);
  }, []);

  const flash = (next: CopyState) => {
    setState(next);
    if (timer.current) clearTimeout(timer.current);
    timer.current = setTimeout(() => setState('idle'), 2000);
  };

  const copy = () => {
    if (!navigator.clipboard) {
      flash('failed');
      return;
    }
    navigator.clipboard.writeText(command).then(
      () => flash('copied'),
      () => flash('failed'),
    );
  };

  const label = state === 'copied' ? 'Copied' : state === 'failed' ? 'Copy failed' : 'Copy';

  return (
    <div className="flex items-stretch gap-2 rounded-lg code-surface border border-border bg-bg-raised p-2">
      <pre tabIndex={0} role="region" aria-label={`${what} (scrollable)`} className="flex-1 overflow-x-auto px-2 py-2 font-mono text-xs text-fg-muted sm:text-sm">
        <code>
          {prompt && <span className="select-none text-brand" aria-hidden="true">$ </span>}
          {command}
        </code>
      </pre>
      <button
        type="button"
        onClick={copy}
        className="min-h-11 min-w-11 shrink-0 rounded-md bg-fg/[0.06] px-3 text-xs font-medium text-fg transition-colors hover:bg-fg/[0.12]"
      >
        {label}
        <span className="sr-only"> {what}</span>
      </button>
      <span className="sr-only" role="status">
        {state === 'copied' ? `${what[0].toUpperCase()}${what.slice(1)} copied to clipboard` : state === 'failed' ? 'Copy failed, select the command and copy it manually' : ''}
      </span>
    </div>
  );
}
