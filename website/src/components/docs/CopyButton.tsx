'use client';

import { useState } from 'react';
import { motion, AnimatePresence } from 'motion/react';

export function CopyButton({ text }: { text: string }) {
  const [copied, setCopied] = useState(false);
  const [failed, setFailed] = useState(false);

  const copy = () => {
    navigator.clipboard.writeText(text).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }).catch(() => {
      setFailed(true);
      setTimeout(() => setFailed(false), 2000);
    });
  };

  const iconKey = failed ? 'failed' : copied ? 'copied' : 'copy';

  return (
    <motion.button
      onClick={copy}
      className="absolute right-2 top-2 flex h-8 w-8 items-center justify-center rounded-md bg-white/10 text-zinc-400 opacity-0 transition-opacity hover:bg-white/15 hover:text-white group-hover:opacity-100"
      aria-label={failed ? 'Copy failed - try Ctrl+C' : copied ? 'Copied' : 'Copy code'}
      title={failed ? 'Clipboard access denied. Try Ctrl+C to copy.' : undefined}
      whileTap={{ scale: 0.85 }}
      transition={{ type: 'spring', stiffness: 400, damping: 17 }}
    >
      <AnimatePresence mode="wait" initial={false}>
        <motion.span
          key={iconKey}
          initial={{ scale: 0, opacity: 0 }}
          animate={{ scale: 1, opacity: 1 }}
          exit={{ scale: 0, opacity: 0 }}
          transition={{ duration: 0.15 }}
          className="block"
        >
          {copied ? (
            <svg className="h-4 w-4 text-accent-green" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M5 13l4 4L19 7" />
            </svg>
          ) : failed ? (
            <svg className="h-4 w-4 text-red-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M6 18L18 6M6 6l12 12" />
            </svg>
          ) : (
            <svg className="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z" />
            </svg>
          )}
        </motion.span>
      </AnimatePresence>
    </motion.button>
  );
}
