'use client';

import React, { type ReactNode, type ComponentPropsWithoutRef } from 'react';
import { CopyButton } from './CopyButton';

function HeadingAnchor({ id, level, children }: { id?: string; level: number; children?: ReactNode }) {
  return React.createElement(
    `h${level}`,
    { id, className: 'group scroll-mt-20' },
    children,
    id
      ? React.createElement(
          'a',
          {
            href: `#${id}`,
            className: 'ml-2 text-fg-subtle opacity-0 transition-opacity group-hover:opacity-100',
            'aria-label': 'Link to heading',
          },
          '#'
        )
      : null
  );
}

export const mdxComponents = {
  h1: (props: ComponentPropsWithoutRef<'h1'>) => <HeadingAnchor level={1} {...props} />,
  h2: (props: ComponentPropsWithoutRef<'h2'>) => <HeadingAnchor level={2} {...props} />,
  h3: (props: ComponentPropsWithoutRef<'h3'>) => <HeadingAnchor level={3} {...props} />,
  h4: (props: ComponentPropsWithoutRef<'h4'>) => <HeadingAnchor level={4} {...props} />,
  h5: (props: ComponentPropsWithoutRef<'h5'>) => <HeadingAnchor level={5} {...props} />,
  h6: (props: ComponentPropsWithoutRef<'h6'>) => <HeadingAnchor level={6} {...props} />,

  a: (props: ComponentPropsWithoutRef<'a'>) => (
    <a {...props} className="text-accent hover:underline" target={props.href?.startsWith('http') ? '_blank' : undefined} rel={props.href?.startsWith('http') ? 'noopener noreferrer' : undefined} />
  ),

  pre: ({ children, ...props }: ComponentPropsWithoutRef<'pre'>) => {
    // Extract text content for copy button
    let codeText = '';
    try {
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const child = children as any;
      if (child?.props?.children) {
        codeText = String(child.props.children);
      }
    } catch {
      // ignore
    }
    return (
      <div className="group relative">
        <CopyButton text={codeText} />
        <pre
          {...props}
          tabIndex={0}
          className="overflow-x-auto rounded-lg border border-fg/5 bg-bg-raised p-4 text-sm focus:outline-none focus:ring-2 focus:ring-ok/50 focus:ring-offset-1 focus:ring-offset-zinc-900"
        >
          {children}
        </pre>
        {/* Mobile scroll hint: right-edge fade gradient, hidden on md+ where scrollbar is visible */}
        <div
          className="pointer-events-none absolute bottom-0 right-0 top-0 w-8 rounded-r-lg bg-gradient-to-l from-bg-raised to-transparent md:hidden"
          aria-hidden="true"
        />
      </div>
    );
  },

  blockquote: (props: ComponentPropsWithoutRef<'blockquote'>) => (
    <blockquote {...props} className="border-l-2 border-accent bg-bg-raised/50 pl-4 py-2 italic text-fg-muted" />
  ),

  table: (props: ComponentPropsWithoutRef<'table'>) => (
    <div className="overflow-x-auto">
      <table {...props} className="w-full text-sm" />
    </div>
  ),
  thead: (props: ComponentPropsWithoutRef<'thead'>) => <thead {...props} className="border-b border-fg/10 text-left text-fg-muted" />,
  th: (props: ComponentPropsWithoutRef<'th'>) => <th {...props} className="px-3 py-2 font-semibold" />,
  td: (props: ComponentPropsWithoutRef<'td'>) => <td {...props} className="border-t border-fg/5 px-3 py-2" />,
  tr: (props: ComponentPropsWithoutRef<'tr'>) => <tr {...props} className="hover:bg-fg/[0.02]" />,
};
