'use client';

import { useRef, useState, type KeyboardEvent } from 'react';
import { m } from 'motion/react';
import { GlassCard } from '@/components/ui/GlassCard';
import { highlightGoLine } from '@/lib/go-highlight';

export type ApiExample = { id: string; label: string; code: string };

function renderCode(code: string) {
  return code.split('\n').map((line, idx) => (
    <div key={idx} className="flex">
      <span className="w-8 text-right text-fg-subtle select-none mr-4 shrink-0" aria-hidden="true">{idx + 1}</span>
      <span className="flex-1 whitespace-pre">
        {line === ''
          ? <>&nbsp;</>
          : highlightGoLine(line).map((seg, i) => (
              <span key={i} className={seg.cls}>{seg.text}</span>
            ))}
      </span>
    </div>
  ));
}

export function CodeExamplesTabs({ examples }: { examples: ApiExample[] }) {
  const [active, setActive] = useState(0);
  const [switched, setSwitched] = useState(false);
  const tabRefs = useRef<(HTMLButtonElement | null)[]>([]);

  const select = (i: number, focus = false) => {
    setActive(i);
    setSwitched(true);
    if (focus) tabRefs.current[i]?.focus();
  };

  const onKeyDown = (e: KeyboardEvent<HTMLButtonElement>, i: number) => {
    const last = examples.length - 1;
    let next: number | null = null;
    if (e.key === 'ArrowRight') next = i === last ? 0 : i + 1;
    else if (e.key === 'ArrowLeft') next = i === 0 ? last : i - 1;
    else if (e.key === 'Home') next = 0;
    else if (e.key === 'End') next = last;
    if (next === null) return;
    e.preventDefault();
    select(next, true);
  };

  return (
    <>
      <div role="tablist" aria-label="API examples" className="flex flex-wrap gap-1 mb-4">
        {examples.map((ex, i) => (
          <button
            key={ex.id}
            ref={(el) => {
              tabRefs.current[i] = el;
            }}
            type="button"
            role="tab"
            id={`api-tab-${ex.id}`}
            aria-selected={active === i}
            aria-controls={`api-panel-${ex.id}`}
            tabIndex={active === i ? 0 : -1}
            onClick={() => select(i)}
            onKeyDown={(e) => onKeyDown(e, i)}
            className={`relative min-h-11 px-4 py-2 text-sm font-medium rounded-t-lg transition-colors ${
              active === i ? 'text-fg' : 'text-fg-subtle hover:text-fg-muted'
            }`}
          >
            {ex.label}
            <span
              aria-hidden="true"
              className={`absolute bottom-0 left-0 right-0 h-0.5 bg-accent origin-left transition-transform duration-300 ease-out ${
                active === i ? 'scale-x-100' : 'scale-x-0'
              }`}
            />
          </button>
        ))}
      </div>
      <GlassCard hover={false} className="p-0 overflow-hidden">
        <div className="flex items-center gap-2 px-4 py-3 border-b border-fg/[0.06]">
          <div aria-hidden="true" className="w-3 h-3 rounded-full bg-dot-red" />
          <div aria-hidden="true" className="w-3 h-3 rounded-full bg-dot-yellow" />
          <div aria-hidden="true" className="w-3 h-3 rounded-full bg-dot-green" />
          <span className="text-xs text-fg-subtle ml-2">main.go</span>
        </div>
        {examples.map((ex, i) => (
          <div
            key={ex.id}
            role="tabpanel"
            id={`api-panel-${ex.id}`}
            aria-labelledby={`api-tab-${ex.id}`}
            hidden={active !== i}
            tabIndex={0}
            className="p-4 font-mono text-sm leading-relaxed overflow-x-auto"
          >
            {active === i && (
              <m.div
                key={ex.id}
                initial={switched ? { opacity: 0, y: 8 } : false}
                animate={{ opacity: 1, y: 0 }}
                transition={{ duration: 0.2 }}
              >
                {renderCode(ex.code)}
              </m.div>
            )}
          </div>
        ))}
      </GlassCard>
    </>
  );
}
