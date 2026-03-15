'use client';
import Link from 'next/link';
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
    { label: 'API Reference', href: '/docs/api-reference' },
    { label: 'Blog', href: '/blog' },
    { label: 'Changelog', href: 'https://github.com/ajitpsingh/GoSQLX/blob/main/CHANGELOG.md', external: true },
    { label: 'Privacy Policy', href: '/privacy' },
  ],
  Community: [
    { label: 'GitHub', href: 'https://github.com/ajitpsingh/GoSQLX', external: true },
    { label: 'Issues', href: 'https://github.com/ajitpsingh/GoSQLX/issues', external: true },
    { label: 'Discussions', href: 'https://github.com/ajitpsingh/GoSQLX/discussions', external: true },
    { label: 'Releases', href: 'https://github.com/ajitpsingh/GoSQLX/releases', external: true },
  ],
};

export function Footer() {
  return (
    <FadeIn>
      <footer className="relative mt-24 border-t border-white/[0.06]">
        {/* Gradient accent line */}
        <div className="absolute top-0 left-0 right-0 h-px bg-gradient-to-r from-transparent via-accent-indigo to-accent-orange opacity-40" />

        <div className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8 py-16">
          <div className="grid grid-cols-2 md:grid-cols-4 gap-8">
            {/* Logo column */}
            <div className="col-span-2 md:col-span-1">
              <Link href="/" className="flex items-center gap-2.5">
                <picture>
                  <source srcSet="/images/logo.webp" type="image/webp" />
                  <img src="/images/logo.png" alt="GoSQLX" width={28} height={28} className="w-7 h-7" />
                </picture>
                <span className="text-lg font-semibold text-white">GoSQLX</span>
              </Link>
              <p className="mt-3 text-sm text-zinc-500 max-w-xs">
                Production-ready SQL parsing SDK for Go. Zero-copy, thread-safe, multi-dialect.
              </p>
            </div>

            {/* Link columns */}
            {Object.entries(FOOTER_LINKS).map(([category, links]) => (
              <div key={category}>
                <h3 className="text-sm font-medium text-zinc-300 mb-3">{category}</h3>
                <ul className="space-y-2">
                  {links.map((link) => (
                    <li key={link.label}>
                      {'external' in link && link.external ? (
                        <a
                          href={link.href}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="text-sm text-zinc-500 hover:text-zinc-300 transition-colors duration-200"
                        >
                          {link.label}
                        </a>
                      ) : (
                        <Link
                          href={link.href}
                          className="text-sm text-zinc-500 hover:text-zinc-300 transition-colors duration-200"
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

          <div className="mt-12 pt-8 border-t border-white/[0.06] text-center">
            <p className="text-sm text-zinc-600">
              Built with love by the GoSQLX community &middot; &copy; {new Date().getFullYear()} GoSQLX
            </p>
          </div>
        </div>
      </footer>
    </FadeIn>
  );
}
