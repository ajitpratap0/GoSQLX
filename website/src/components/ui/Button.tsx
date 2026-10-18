'use client';
import Link from 'next/link';
import { m } from 'motion/react';

type ButtonProps = {
  variant?: 'primary' | 'ghost';
  href?: string;
  children: React.ReactNode;
  className?: string;
  external?: boolean;
  'aria-label'?: string;
};

// The motion props live on the <a> itself: a wrapper <div> with whileTap gets an
// auto tabindex from Motion, which gave every CTA two keyboard tab stops.
const MotionLink = m.create(Link);

const spring = { type: 'spring' as const, stiffness: 400, damping: 17 };

export function Button({ variant = 'primary', href, children, className = '', external, 'aria-label': ariaLabel }: ButtonProps) {
  const base = variant === 'primary'
    ? 'bg-fg text-bg hover:bg-fg-muted'
    : 'bg-fg/[0.06] border border-fg/[0.1] text-fg-muted hover:bg-fg/[0.1] hover:text-fg';
  const cls = `inline-flex items-center gap-2 px-5 py-2.5 rounded-lg font-medium text-sm transition-colors duration-200 ${base} ${className}`;

  if (href) {
    if (external) {
      return (
        <m.a
          href={href}
          target="_blank"
          rel="noopener noreferrer"
          className={cls}
          aria-label={ariaLabel}
          whileHover={{ scale: 1.02 }}
          whileTap={{ scale: 0.97 }}
          transition={spring}
        >
          {children}
        </m.a>
      );
    }
    return (
      <MotionLink
        href={href}
        className={cls}
        aria-label={ariaLabel}
        whileHover={{ scale: 1.02 }}
        whileTap={{ scale: 0.97 }}
        transition={spring}
      >
        {children}
      </MotionLink>
    );
  }
  return (
    <m.button
      className={cls}
      aria-label={ariaLabel}
      whileHover={{ scale: 1.02 }}
      whileTap={{ scale: 0.97 }}
      transition={spring}
    >
      {children}
    </m.button>
  );
}
