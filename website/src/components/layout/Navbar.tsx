'use client';
import Link from 'next/link';
import Image from 'next/image';
import { useState, useEffect } from 'react';
import { usePathname } from 'next/navigation';
import { motion, AnimatePresence, useScroll, useTransform } from 'framer-motion';
import { NAV_LINKS } from '@/lib/constants';
import { Button } from '@/components/ui/Button';
import { SearchModal, useSearchShortcut } from '@/components/ui/SearchModal';
import { ThemeToggle } from '@/components/ui/ThemeToggle';

function GitHubIcon({ className = '' }: { className?: string }) {
  return (
    <svg viewBox="0 0 24 24" fill="currentColor" className={className} aria-hidden="true">
      <path d="M12 0C5.37 0 0 5.37 0 12c0 5.31 3.435 9.795 8.205 11.385.6.105.825-.255.825-.57 0-.285-.015-1.23-.015-2.235-3.015.555-3.795-.735-4.035-1.41-.135-.345-.72-1.41-1.23-1.695-.42-.225-1.02-.78-.015-.795.945-.015 1.62.87 1.845 1.23 1.08 1.815 2.805 1.305 3.495.99.105-.78.42-1.305.765-1.605-2.67-.3-5.46-1.335-5.46-5.925 0-1.305.465-2.385 1.23-3.225-.12-.3-.54-1.53.12-3.18 0 0 1.005-.315 3.3 1.23.96-.27 1.98-.405 3-.405s2.04.135 3 .405c2.295-1.56 3.3-1.23 3.3-1.23.66 1.65.24 2.88.12 3.18.765.84 1.23 1.905 1.23 3.225 0 4.605-2.805 5.625-5.475 5.925.435.375.81 1.095.81 2.22 0 1.605-.015 2.895-.015 3.3 0 .315.225.69.825.57A12.02 12.02 0 0024 12c0-6.63-5.37-12-12-12z" />
    </svg>
  );
}

function HamburgerIcon({ open }: { open: boolean }) {
  return (
    <div className="w-5 h-4 relative flex flex-col justify-between">
      <motion.span
        className="block h-0.5 w-full bg-zinc-300 rounded-full origin-center"
        animate={open ? { rotate: 45, y: 7 } : { rotate: 0, y: 0 }}
        transition={{ duration: 0.2 }}
      />
      <motion.span
        className="block h-0.5 w-full bg-zinc-300 rounded-full"
        animate={open ? { opacity: 0 } : { opacity: 1 }}
        transition={{ duration: 0.15 }}
      />
      <motion.span
        className="block h-0.5 w-full bg-zinc-300 rounded-full origin-center"
        animate={open ? { rotate: -45, y: -7 } : { rotate: 0, y: 0 }}
        transition={{ duration: 0.2 }}
      />
    </div>
  );
}

export function Navbar() {
  const [mobileOpen, setMobileOpen] = useState(false);
  const pathname = usePathname();
  const { open: searchOpen, setOpen: setSearchOpen } = useSearchShortcut();
  const { scrollY } = useScroll();
  const bgOpacity = useTransform(scrollY, [0, 100], [0.6, 0.9]);
  const blurAmount = useTransform(scrollY, [0, 100], [8, 16]);
  const bgColor = useTransform(bgOpacity, (v) => `rgba(9, 9, 11, ${v})`);
  const blur = useTransform(blurAmount, (v) => `blur(${v}px)`);

  // Close mobile menu on resize
  useEffect(() => {
    const handler = () => { if (window.innerWidth >= 1024) setMobileOpen(false); };
    window.addEventListener('resize', handler);
    return () => window.removeEventListener('resize', handler);
  }, []);

  // Lock body scroll when mobile menu is open
  useEffect(() => {
    if (mobileOpen) {
      document.body.style.overflow = 'hidden';
    } else {
      document.body.style.overflow = '';
    }
    return () => { document.body.style.overflow = ''; };
  }, [mobileOpen]);

  return (
    <>
    <motion.header
      className="fixed top-0 left-0 right-0 z-50 border-b border-white/[0.06]"
      style={{
        backgroundColor: bgColor,
        backdropFilter: blur,
      }}
    >
      <nav aria-label="Main navigation" className="mx-auto max-w-7xl flex items-center justify-between px-4 sm:px-6 lg:px-8 h-16">
        {/* Logo */}
        <Link href="/" className="flex items-center gap-2.5 shrink-0">
          <Image src="/images/logo.webp" alt="GoSQLX logo" width={32} height={32} priority />
          <span className="text-lg font-semibold text-white">GoSQLX</span>
        </Link>

        {/* Desktop nav links */}
        <div className="hidden lg:flex items-center gap-1">
          {NAV_LINKS.map((link) => {
            const isActive = pathname === link.href || pathname.startsWith(link.href + '/');
            return (
              <Link
                key={link.href}
                href={link.href}
                aria-current={isActive ? 'page' : undefined}
                className={`px-3 py-2 text-sm transition-colors duration-200 rounded-lg hover:bg-white/[0.04] ${isActive ? 'text-white' : 'text-zinc-300 hover:text-white'}`}
              >
                {link.label}
              </Link>
            );
          })}
        </div>

        {/* Desktop right side */}
        <div className="hidden lg:flex items-center gap-3">
          <button
            type="button"
            onClick={() => setSearchOpen(true)}
            className="inline-flex items-center gap-2 rounded-lg border border-white/[0.08] bg-white/[0.03] px-3 py-1.5 text-sm text-zinc-400 transition-colors hover:border-white/[0.12] hover:bg-white/[0.06] hover:text-zinc-300"
            aria-label="Search documentation"
          >
            <svg className="h-3.5 w-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M21 21l-5.197-5.197m0 0A7.5 7.5 0 105.196 5.196a7.5 7.5 0 0010.607 10.607z" />
            </svg>
            <span className="hidden xl:inline">Search</span>
            <kbd className="font-mono text-[10px] text-zinc-600 border border-white/[0.08] rounded px-1 py-0.5 bg-white/[0.03]">&#8984;K</kbd>
          </button>
          <a
            href="https://github.com/ajitpratap0/GoSQLX"
            target="_blank"
            rel="noopener noreferrer"
            className="text-zinc-300 hover:text-white transition-colors duration-200 p-2 rounded-lg hover:bg-white/[0.04]"
            aria-label="GitHub"
          >
            <GitHubIcon className="w-5 h-5" />
          </a>
          <ThemeToggle />
          <Button href="/docs/getting-started" variant="primary" className="text-xs px-4 py-2">
            Get Started
          </Button>
        </div>

        {/* Mobile hamburger */}
        <button
          type="button"
          className="lg:hidden w-11 h-11 flex items-center justify-center rounded-lg hover:bg-white/[0.04] transition-colors"
          onClick={() => setMobileOpen(!mobileOpen)}
          aria-label="Toggle menu"
          aria-expanded={mobileOpen}
          aria-controls="mobile-menu"
        >
          <HamburgerIcon open={mobileOpen} />
        </button>
      </nav>

      {/* Mobile menu */}
      <AnimatePresence>
        {mobileOpen && (
          <motion.div
            id="mobile-menu"
            initial={{ height: 0, opacity: 0, pointerEvents: 'none' }}
            animate={{ height: 'auto', opacity: 1, pointerEvents: 'auto' }}
            exit={{ height: 0, opacity: 0, pointerEvents: 'none' }}
            transition={{ duration: 0.25, ease: 'easeInOut' }}
            className="lg:hidden overflow-hidden border-t border-white/[0.06] bg-primary backdrop-blur-xl"
          >
            <div className="px-4 py-4 space-y-1">
              {NAV_LINKS.map((link) => {
                const isActive = pathname === link.href || pathname.startsWith(link.href + '/');
                return (
                  <Link
                    key={link.href}
                    href={link.href}
                    onClick={() => setMobileOpen(false)}
                    aria-current={isActive ? 'page' : undefined}
                    className={`block px-3 py-2.5 text-sm hover:bg-white/[0.04] rounded-lg transition-colors ${isActive ? 'text-white' : 'text-zinc-300 hover:text-white'}`}
                  >
                    {link.label}
                  </Link>
                );
              })}
              <div className="pt-3 border-t border-white/[0.06] flex items-center gap-3">
                <a
                  href="https://github.com/ajitpratap0/GoSQLX"
                  target="_blank"
                  rel="noopener noreferrer"
                  className="text-zinc-300 hover:text-white transition-colors p-2"
                  aria-label="GitHub"
                >
                  <GitHubIcon className="w-5 h-5" />
                </a>
                <ThemeToggle />
                <Button href="/docs/getting-started" variant="primary" className="text-xs px-4 py-2">
                  Get Started
                </Button>
              </div>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </motion.header>
    <SearchModal open={searchOpen} onClose={() => setSearchOpen(false)} />
    </>
  );
}
