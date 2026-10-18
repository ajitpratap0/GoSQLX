// Server module on purpose: a 'use client' file can only export components, and
// an exported object map would reach compileMDX as a client reference, silently
// dropping every override below (no copy buttons, no heading anchors).
import React, { type ReactNode, type ComponentPropsWithoutRef } from 'react';
import { CodeBlock } from '@/components/ui/CodeBlock';

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

  pre: ({ children, className, ...props }: ComponentPropsWithoutRef<'pre'>) => (
    <CodeBlock>
      <pre {...props} tabIndex={0} className={className}>
        {children}
      </pre>
    </CodeBlock>
  ),

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
