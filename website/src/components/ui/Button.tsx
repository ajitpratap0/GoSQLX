'use client';
import Link from 'next/link';
import { motion } from 'motion/react';

type ButtonProps = {
  variant?: 'primary' | 'ghost';
  href?: string;
  children: React.ReactNode;
  className?: string;
  external?: boolean;
  'aria-label'?: string;
};

const spring = { type: 'spring' as const, stiffness: 400, damping: 17 };

export function Button({ variant = 'primary', href, children, className = '', external, 'aria-label': ariaLabel }: ButtonProps) {
  const base = variant === 'primary'
    ? 'bg-white text-zinc-950 hover:bg-zinc-200'
    : 'bg-white/[0.06] border border-white/[0.1] text-zinc-300 hover:bg-white/[0.1] hover:text-white';
  const cls = `inline-flex items-center gap-2 px-5 py-2.5 rounded-lg font-medium text-sm transition-colors duration-200 ${base} ${className}`;

  if (href) {
    if (external) {
      return (
        <motion.a
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
        </motion.a>
      );
    }
    return (
      <motion.div whileHover={{ scale: 1.02 }} whileTap={{ scale: 0.97 }} transition={spring} className="inline-flex">
        <Link href={href} className={cls} aria-label={ariaLabel}>{children}</Link>
      </motion.div>
    );
  }
  return (
    <motion.button
      className={cls}
      aria-label={ariaLabel}
      whileHover={{ scale: 1.02 }}
      whileTap={{ scale: 0.97 }}
      transition={spring}
    >
      {children}
    </motion.button>
  );
}
