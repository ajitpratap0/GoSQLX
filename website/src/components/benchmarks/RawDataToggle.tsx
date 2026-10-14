'use client';

import { useState } from 'react';

export function RawDataToggle({ id, children }: { id: string; children: React.ReactNode }) {
  const [open, setOpen] = useState(false);
  const panelId = `raw-data-${id}`;

  return (
    <div className="mt-4">
      <button
        type="button"
        onClick={() => setOpen((prev) => !prev)}
        className="text-xs text-zinc-500 hover:text-zinc-300 transition-colors flex items-center gap-1"
        aria-expanded={open}
        aria-controls={panelId}
      >
        <svg
          className={`w-3 h-3 transition-transform duration-200 motion-reduce:transition-none ${open ? 'rotate-90' : ''}`}
          fill="none"
          viewBox="0 0 24 24"
          stroke="currentColor"
          strokeWidth={2}
          aria-hidden="true"
        >
          <path strokeLinecap="round" strokeLinejoin="round" d="M9 5l7 7-7 7" />
        </svg>
        {open ? 'Hide' : 'View'} raw data
      </button>
      <div
        id={panelId}
        className={`grid transition-[grid-template-rows,opacity] duration-300 ease-out motion-reduce:transition-none ${
          open ? 'grid-rows-[1fr] opacity-100' : 'grid-rows-[0fr] opacity-0'
        }`}
        aria-hidden={!open}
      >
        <div className="overflow-hidden" {...(open ? {} : { inert: true })}>
          <div className="mt-3">{children}</div>
        </div>
      </div>
    </div>
  );
}
