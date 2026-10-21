'use client';
import Link from 'next/link';
import Image from 'next/image';
import { FadeIn } from '@/components/ui/FadeIn';

const FOOTER_LINKS = {
  Product: [
    { label: 'Documentation', href: '/docs' },
    { label: 'Playground', href: '/playground' },
    { label: 'VS Code Extension', href: '/vscode' },
    { label: 'Benchmarks', href: '/benchmarks' },
    { label: 'CLI', href: '/docs/cli-guide' },
  ],
  Resources: [
    { label: 'Getting Started', href: '/docs/getting-started' },
    { label: 'API Reference', href: '/docs/reference/api/' },
    { label: 'Compare Parsers', href: '/compare' },
    { label: 'Blog', href: '/blog' },
    { label: 'Changelog', href: '/changelog' },
    { label: 'CHANGELOG.md on GitHub', href: 'https://github.com/ajitpratap0/GoSQLX/blob/main/CHANGELOG.md', external: true },
    { label: 'Privacy Policy', href: '/privacy' },
    { label: 'Terms of Service', href: '/terms' },
  ],
  Community: [
    { label: 'GitHub', href: 'https://github.com/ajitpratap0/GoSQLX', external: true },
    { label: 'Issues', href: 'https://github.com/ajitpratap0/GoSQLX/issues', external: true },
    { label: 'Discussions', href: 'https://github.com/ajitpratap0/GoSQLX/discussions', external: true },
    { label: 'Releases', href: 'https://github.com/ajitpratap0/GoSQLX/releases', external: true },
    { label: 'Release RSS', href: 'https://github.com/ajitpratap0/GoSQLX/releases.atom', external: true },
  ],
};

export function Footer() {
  return (
    <FadeIn>
      <footer className="relative mt-24 border-t border-fg/[0.06]">
        {/* Gradient accent line */}
        <div className="absolute top-0 left-0 right-0 h-px bg-gradient-to-r from-transparent via-accent to-accent-warm-decor opacity-40" />

        <div className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8 py-16">
          <div className="grid grid-cols-2 md:grid-cols-4 gap-8">
            {/* Logo column */}
            <div className="col-span-2 md:col-span-1">
              <Link href="/" className="flex items-center gap-2.5">
                <Image src="/images/logo.webp" alt="" width={28} height={28} />
                <span className="text-lg font-semibold text-fg">GoSQLX</span>
              </Link>
              <p className="mt-3 text-sm text-fg-muted max-w-xs">
                Production-ready SQL parsing SDK for Go. Zero-copy, thread-safe, multi-dialect.
              </p>
            </div>

            {/* Link columns */}
            {Object.entries(FOOTER_LINKS).map(([category, links]) => (
              <div key={category}>
                <h3 className="text-sm font-medium text-fg-muted mb-3">{category}</h3>
                <ul>
                  {links.map((link) => (
                    <li key={link.href}>
                      {'external' in link && link.external ? (
                        <a
                          href={link.href}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="inline-flex min-h-11 items-center text-sm text-fg-muted hover:text-fg transition-colors duration-200"
                        >
                          {link.label}
                        </a>
                      ) : (
                        <Link
                          href={link.href}
                          className="inline-flex min-h-11 items-center text-sm text-fg-muted hover:text-fg transition-colors duration-200"
                        >
                          {link.label}
                        </Link>
                      )}
                    </li>
                  ))}
                </ul>
              </div>
            ))}
          </div>

          <div className="mt-12 pt-8 border-t border-fg/[0.06] text-center">
            <p className="text-sm text-fg-muted">
              Built with love by the GoSQLX community &middot; &copy; {new Date().getFullYear()} GoSQLX
            </p>
          </div>
        </div>
      </footer>
    </FadeIn>
  );
}
