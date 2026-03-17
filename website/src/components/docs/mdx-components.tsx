'use client';

import React, { useState, type ReactNode, type ComponentPropsWithoutRef } from 'react';

function CopyButton({ text }: { text: string }) {
  const [copied, setCopied] = useState(false);

  const copy = () => {
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <button
      onClick={copy}
      className="absolute right-2 top-2 rounded bg-white/10 px-2 py-1 text-xs text-zinc-400 opacity-0 transition-opacity hover:text-white group-hover:opacity-100"
      aria-label="Copy code"
    >
      {copied ? 'Copied!' : 'Copy'}
    </button>
  );
}

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
            className: 'ml-2 text-zinc-600 opacity-0 transition-opacity group-hover:opacity-100',
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
    <a {...props} className="text-accent-indigo hover:underline" target={props.href?.startsWith('http') ? '_blank' : undefined} rel={props.href?.startsWith('http') ? 'noopener noreferrer' : undefined} />
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
          className="overflow-x-auto rounded-lg border border-white/5 bg-surface p-4 text-sm focus:outline-none focus:ring-2 focus:ring-emerald-500/50 focus:ring-offset-1 focus:ring-offset-zinc-900"
        >
          {children}
        </pre>
      </div>
    );
  },

  code: (props: ComponentPropsWithoutRef<'code'>) => {
    // Inline code (not inside pre)
    const isInline = !props.className;
    if (isInline) {
      return <code {...props} className="rounded bg-white/10 px-1.5 py-0.5 text-sm font-mono text-zinc-200" />;
    }
    return <code {...props} />;
  },

  blockquote: (props: ComponentPropsWithoutRef<'blockquote'>) => (
    <blockquote {...props} className="border-l-2 border-accent-indigo bg-surface/50 pl-4 py-2 italic text-zinc-400" />
  ),

  table: (props: ComponentPropsWithoutRef<'table'>) => (
    <div className="overflow-x-auto">
      <table {...props} className="w-full text-sm" />
    </div>
  ),
  thead: (props: ComponentPropsWithoutRef<'thead'>) => <thead {...props} className="border-b border-white/10 text-left text-zinc-400" />,
  th: (props: ComponentPropsWithoutRef<'th'>) => <th {...props} className="px-3 py-2 font-semibold" />,
  td: (props: ComponentPropsWithoutRef<'td'>) => <td {...props} className="border-t border-white/5 px-3 py-2" />,
  tr: (props: ComponentPropsWithoutRef<'tr'>) => <tr {...props} className="hover:bg-white/[0.02]" />,
};
