'use client';

import { useState } from 'react';
import { m } from 'motion/react';
import { GlassCard } from '@/components/ui/GlassCard';
import { FadeIn } from '@/components/ui/FadeIn';

type Segment = { text: string; cls: string };
type CodeLine = Segment[];

const tabs: { label: string; lines: CodeLine[] }[] = [
  {
    label: 'Parse',
    lines: [
      [{ text: 'package', cls: 'text-accent' }, { text: ' main', cls: 'text-fg' }],
      [],
      [{ text: 'import', cls: 'text-accent' }, { text: ' ', cls: '' }, { text: '"github.com/ajitpratap0/GoSQLX/pkg/gosqlx"', cls: 'text-brand' }],
      [],
      [{ text: 'func', cls: 'text-accent' }, { text: ' main', cls: 'text-accent-warm' }, { text: '() {', cls: 'text-fg-muted' }],
      [{ text: '    ', cls: '' }, { text: '// Parse SQL into an AST', cls: 'text-fg-subtle' }],
      [{ text: '    ast, err := gosqlx.', cls: 'text-fg-muted' }, { text: 'Parse', cls: 'text-accent-warm' }, { text: '(', cls: 'text-fg-muted' }, { text: '"SELECT * FROM users WHERE active = true"', cls: 'text-brand' }, { text: ')', cls: 'text-fg-muted' }],
      [{ text: '    ', cls: '' }, { text: 'if', cls: 'text-accent' }, { text: ' err != nil {', cls: 'text-fg-muted' }],
      [{ text: '        log.Fatal(err)', cls: 'text-fg-muted' }],
      [{ text: '    }', cls: 'text-fg-muted' }],
      [{ text: '    fmt.Println(ast.Statements)', cls: 'text-fg-muted' }],
      [{ text: '}', cls: 'text-fg-muted' }],
    ],
  },
  {
    label: 'Format',
    lines: [
      [{ text: 'package', cls: 'text-accent' }, { text: ' main', cls: 'text-fg' }],
      [],
      [{ text: 'import', cls: 'text-accent' }, { text: ' ', cls: '' }, { text: '"github.com/ajitpratap0/GoSQLX/pkg/gosqlx"', cls: 'text-brand' }],
      [],
      [{ text: 'func', cls: 'text-accent' }, { text: ' main', cls: 'text-accent-warm' }, { text: '() {', cls: 'text-fg-muted' }],
      [{ text: '    ', cls: '' }, { text: '// Format messy SQL', cls: 'text-fg-subtle' }],
      [{ text: '    formatted, err := gosqlx.', cls: 'text-fg-muted' }, { text: 'Format', cls: 'text-accent-warm' }, { text: '(', cls: 'text-fg-muted' }, { text: '"select id,name from users where id>5"', cls: 'text-brand' }, { text: ')', cls: 'text-fg-muted' }],
      [{ text: '    ', cls: '' }, { text: 'if', cls: 'text-accent' }, { text: ' err != nil {', cls: 'text-fg-muted' }],
      [{ text: '        log.Fatal(err)', cls: 'text-fg-muted' }],
      [{ text: '    }', cls: 'text-fg-muted' }],
      [{ text: '    fmt.Println(formatted)', cls: 'text-fg-muted' }],
      [{ text: '}', cls: 'text-fg-muted' }],
    ],
  },
  {
    label: 'Validate',
    lines: [
      [{ text: 'package', cls: 'text-accent' }, { text: ' main', cls: 'text-fg' }],
      [],
      [{ text: 'import', cls: 'text-accent' }, { text: ' ', cls: '' }, { text: '"github.com/ajitpratap0/GoSQLX/pkg/gosqlx"', cls: 'text-brand' }],
      [],
      [{ text: 'func', cls: 'text-accent' }, { text: ' main', cls: 'text-accent-warm' }, { text: '() {', cls: 'text-fg-muted' }],
      [{ text: '    ', cls: '' }, { text: '// Validate SQL syntax', cls: 'text-fg-subtle' }],
      [{ text: '    result := gosqlx.', cls: 'text-fg-muted' }, { text: 'Validate', cls: 'text-accent-warm' }, { text: '(', cls: 'text-fg-muted' }, { text: '"SELECT * FROM users"', cls: 'text-brand' }, { text: ')', cls: 'text-fg-muted' }],
      [{ text: '    ', cls: '' }, { text: 'if', cls: 'text-accent' }, { text: ' result.Valid {', cls: 'text-fg-muted' }],
      [{ text: '        fmt.Println(', cls: 'text-fg-muted' }, { text: '"SQL is valid!"', cls: 'text-brand' }, { text: ')', cls: 'text-fg-muted' }],
      [{ text: '    }', cls: 'text-fg-muted' }],
      [{ text: '}', cls: 'text-fg-muted' }],
    ],
  },
  {
    label: 'Lint',
    lines: [
      [{ text: 'package', cls: 'text-accent' }, { text: ' main', cls: 'text-fg' }],
      [],
      [{ text: 'import', cls: 'text-accent' }, { text: ' ', cls: '' }, { text: '"github.com/ajitpratap0/GoSQLX/pkg/gosqlx"', cls: 'text-brand' }],
      [],
      [{ text: 'func', cls: 'text-accent' }, { text: ' main', cls: 'text-accent-warm' }, { text: '() {', cls: 'text-fg-muted' }],
      [{ text: '    ', cls: '' }, { text: '// Lint SQL for best practices', cls: 'text-fg-subtle' }],
      [{ text: '    issues, err := gosqlx.', cls: 'text-fg-muted' }, { text: 'Lint', cls: 'text-accent-warm' }, { text: '(', cls: 'text-fg-muted' }, { text: '"SELECT * FROM orders"', cls: 'text-brand' }, { text: ')', cls: 'text-fg-muted' }],
      [{ text: '    ', cls: '' }, { text: 'if', cls: 'text-accent' }, { text: ' err != nil {', cls: 'text-fg-muted' }],
      [{ text: '        log.Fatal(err)', cls: 'text-fg-muted' }],
      [{ text: '    }', cls: 'text-fg-muted' }],
      [],
      [{ text: '    ', cls: '' }, { text: 'for', cls: 'text-accent' }, { text: ' _, issue := ', cls: 'text-fg-muted' }, { text: 'range', cls: 'text-accent' }, { text: ' issues {', cls: 'text-fg-muted' }],
      [{ text: '        fmt.Printf(', cls: 'text-fg-muted' }, { text: '"%s: %s\\n"', cls: 'text-brand' }, { text: ', issue.Code, issue.Message)', cls: 'text-fg-muted' }],
      [{ text: '    }', cls: 'text-fg-muted' }],
      [{ text: '}', cls: 'text-fg-muted' }],
    ],
  },
];

function renderCode(lines: CodeLine[]) {
  return lines.map((line, idx) => (
    <div key={idx} className="flex">
      <span className="w-8 text-right text-fg-subtle select-none mr-4 shrink-0">{idx + 1}</span>
      <span className="flex-1 whitespace-pre">
        {line.length === 0
          ? <>&nbsp;</>
          : line.map((seg, i) => (
              <span key={i} className={seg.cls}>{seg.text}</span>
            ))
        }
      </span>
    </div>
  ));
}

export function CodeExamples() {
  const [active, setActive] = useState(0);
  const [switched, setSwitched] = useState(false);

  return (
    <section className="py-20 border-t border-fg/[0.06]">
      <div className="max-w-3xl mx-auto px-4">
        <FadeIn viewport>
          <h2 className="text-3xl font-bold text-fg text-center mb-10">
            Simple, Powerful API
          </h2>
        </FadeIn>
        <FadeIn viewport delay={0.1}>
          <div className="flex flex-wrap gap-1 mb-4">
            {tabs.map((tab, i) => (
              <button
                key={tab.label}
                onClick={() => {
                  setActive(i);
                  setSwitched(true);
                }}
                className={`relative px-4 py-2 text-sm font-medium rounded-t-lg transition-colors ${
                  active === i ? 'text-fg' : 'text-fg-subtle hover:text-fg-muted'
                }`}
              >
                {tab.label}
                <span
                  aria-hidden="true"
                  className={`absolute bottom-0 left-0 right-0 h-0.5 bg-accent origin-left transition-transform duration-300 ease-out ${
                    active === i ? 'scale-x-100' : 'scale-x-0'
                  }`}
                />
              </button>
            ))}
          </div>
          <GlassCard hover={false} className="p-0 overflow-hidden">
            <div className="flex items-center gap-2 px-4 py-3 border-b border-fg/[0.06]">
              <div className="w-3 h-3 rounded-full bg-danger/60" />
              <div className="w-3 h-3 rounded-full bg-warn/60" />
              <div className="w-3 h-3 rounded-full bg-ok/60" />
              <span className="text-xs text-fg-subtle ml-2">main.go</span>
            </div>
            <div className="p-4 font-mono text-sm leading-relaxed overflow-x-auto">
              <m.div
                key={active}
                initial={switched ? { opacity: 0, y: 8 } : false}
                animate={{ opacity: 1, y: 0 }}
                transition={{ duration: 0.2 }}
              >
                {renderCode(tabs[active].lines)}
              </m.div>
            </div>
          </GlassCard>
        </FadeIn>
      </div>
    </section>
  );
}
