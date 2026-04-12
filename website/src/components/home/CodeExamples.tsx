'use client';

import { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { GlassCard } from '@/components/ui/GlassCard';
import { FadeInCSS } from '@/components/ui/FadeInCSS';

type Segment = { text: string; cls: string };
type CodeLine = Segment[];

const tabs: { label: string; lines: CodeLine[] }[] = [
  {
    label: 'Parse',
    lines: [
      [{ text: 'package', cls: 'text-accent-indigo' }, { text: ' main', cls: 'text-white' }],
      [],
      [{ text: 'import', cls: 'text-accent-indigo' }, { text: ' ', cls: '' }, { text: '"github.com/ajitpratap0/GoSQLX/pkg/gosqlx"', cls: 'text-accent-green' }],
      [],
      [{ text: 'func', cls: 'text-accent-indigo' }, { text: ' main', cls: 'text-accent-orange' }, { text: '() {', cls: 'text-zinc-300' }],
      [{ text: '    ', cls: '' }, { text: '// Parse SQL into an AST', cls: 'text-zinc-500' }],
      [{ text: '    ast, err := gosqlx.', cls: 'text-zinc-300' }, { text: 'Parse', cls: 'text-accent-orange' }, { text: '(', cls: 'text-zinc-300' }, { text: '"SELECT * FROM users WHERE active = true"', cls: 'text-accent-green' }, { text: ')', cls: 'text-zinc-300' }],
      [{ text: '    ', cls: '' }, { text: 'if', cls: 'text-accent-indigo' }, { text: ' err != nil {', cls: 'text-zinc-300' }],
      [{ text: '        log.Fatal(err)', cls: 'text-zinc-300' }],
      [{ text: '    }', cls: 'text-zinc-300' }],
      [{ text: '    fmt.Println(ast.Statements)', cls: 'text-zinc-300' }],
      [{ text: '}', cls: 'text-zinc-300' }],
    ],
  },
  {
    label: 'Format',
    lines: [
      [{ text: 'package', cls: 'text-accent-indigo' }, { text: ' main', cls: 'text-white' }],
      [],
      [{ text: 'import', cls: 'text-accent-indigo' }, { text: ' ', cls: '' }, { text: '"github.com/ajitpratap0/GoSQLX/pkg/gosqlx"', cls: 'text-accent-green' }],
      [],
      [{ text: 'func', cls: 'text-accent-indigo' }, { text: ' main', cls: 'text-accent-orange' }, { text: '() {', cls: 'text-zinc-300' }],
      [{ text: '    ', cls: '' }, { text: '// Format messy SQL', cls: 'text-zinc-500' }],
      [{ text: '    formatted, err := gosqlx.', cls: 'text-zinc-300' }, { text: 'Format', cls: 'text-accent-orange' }, { text: '(', cls: 'text-zinc-300' }, { text: '"select id,name from users where id>5"', cls: 'text-accent-green' }, { text: ')', cls: 'text-zinc-300' }],
      [{ text: '    ', cls: '' }, { text: 'if', cls: 'text-accent-indigo' }, { text: ' err != nil {', cls: 'text-zinc-300' }],
      [{ text: '        log.Fatal(err)', cls: 'text-zinc-300' }],
      [{ text: '    }', cls: 'text-zinc-300' }],
      [{ text: '    fmt.Println(formatted)', cls: 'text-zinc-300' }],
      [{ text: '}', cls: 'text-zinc-300' }],
    ],
  },
  {
    label: 'Validate',
    lines: [
      [{ text: 'package', cls: 'text-accent-indigo' }, { text: ' main', cls: 'text-white' }],
      [],
      [{ text: 'import', cls: 'text-accent-indigo' }, { text: ' ', cls: '' }, { text: '"github.com/ajitpratap0/GoSQLX/pkg/gosqlx"', cls: 'text-accent-green' }],
      [],
      [{ text: 'func', cls: 'text-accent-indigo' }, { text: ' main', cls: 'text-accent-orange' }, { text: '() {', cls: 'text-zinc-300' }],
      [{ text: '    ', cls: '' }, { text: '// Validate SQL syntax', cls: 'text-zinc-500' }],
      [{ text: '    result := gosqlx.', cls: 'text-zinc-300' }, { text: 'Validate', cls: 'text-accent-orange' }, { text: '(', cls: 'text-zinc-300' }, { text: '"SELECT * FROM users"', cls: 'text-accent-green' }, { text: ')', cls: 'text-zinc-300' }],
      [{ text: '    ', cls: '' }, { text: 'if', cls: 'text-accent-indigo' }, { text: ' result.Valid {', cls: 'text-zinc-300' }],
      [{ text: '        fmt.Println(', cls: 'text-zinc-300' }, { text: '"SQL is valid!"', cls: 'text-accent-green' }, { text: ')', cls: 'text-zinc-300' }],
      [{ text: '    }', cls: 'text-zinc-300' }],
      [{ text: '}', cls: 'text-zinc-300' }],
    ],
  },
  {
    label: 'Lint',
    lines: [
      [{ text: 'package', cls: 'text-accent-indigo' }, { text: ' main', cls: 'text-white' }],
      [],
      [{ text: 'import', cls: 'text-accent-indigo' }, { text: ' ', cls: '' }, { text: '"github.com/ajitpratap0/GoSQLX/pkg/gosqlx"', cls: 'text-accent-green' }],
      [],
      [{ text: 'func', cls: 'text-accent-indigo' }, { text: ' main', cls: 'text-accent-orange' }, { text: '() {', cls: 'text-zinc-300' }],
      [{ text: '    ', cls: '' }, { text: '// Lint SQL for best practices', cls: 'text-zinc-500' }],
      [{ text: '    issues, err := gosqlx.', cls: 'text-zinc-300' }, { text: 'Lint', cls: 'text-accent-orange' }, { text: '(', cls: 'text-zinc-300' }, { text: '"SELECT * FROM orders"', cls: 'text-accent-green' }, { text: ')', cls: 'text-zinc-300' }],
      [{ text: '    ', cls: '' }, { text: 'if', cls: 'text-accent-indigo' }, { text: ' err != nil {', cls: 'text-zinc-300' }],
      [{ text: '        log.Fatal(err)', cls: 'text-zinc-300' }],
      [{ text: '    }', cls: 'text-zinc-300' }],
      [],
      [{ text: '    ', cls: '' }, { text: 'for', cls: 'text-accent-indigo' }, { text: ' _, issue := ', cls: 'text-zinc-300' }, { text: 'range', cls: 'text-accent-indigo' }, { text: ' issues {', cls: 'text-zinc-300' }],
      [{ text: '        fmt.Printf(', cls: 'text-zinc-300' }, { text: '"%s: %s\\n"', cls: 'text-accent-green' }, { text: ', issue.Code, issue.Message)', cls: 'text-zinc-300' }],
      [{ text: '    }', cls: 'text-zinc-300' }],
      [{ text: '}', cls: 'text-zinc-300' }],
    ],
  },
];

function renderCode(lines: CodeLine[]) {
  return lines.map((line, idx) => (
    <div key={idx} className="flex">
      <span className="w-8 text-right text-zinc-600 select-none mr-4 shrink-0">{idx + 1}</span>
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

  return (
    <section className="py-20 border-t border-white/[0.06]">
      <div className="max-w-3xl mx-auto px-4">
        <FadeInCSS>
          <h2 className="text-3xl font-bold text-white text-center mb-10">
            Simple, Powerful API
          </h2>
        </FadeInCSS>
        <FadeInCSS delay={0.1}>
          <div className="flex flex-wrap gap-1 mb-4">
            {tabs.map((tab, i) => (
              <button
                key={tab.label}
                onClick={() => setActive(i)}
                className={`relative px-4 py-2 text-sm font-medium rounded-t-lg transition-colors ${
                  active === i ? 'text-white' : 'text-zinc-500 hover:text-zinc-300'
                }`}
              >
                {tab.label}
                {active === i && (
                  <motion.div
                    layoutId="activeTab"
                    className="absolute bottom-0 left-0 right-0 h-0.5 bg-accent-indigo"
                    transition={{ type: 'spring', stiffness: 300, damping: 30 }}
                  />
                )}
              </button>
            ))}
          </div>
          <GlassCard hover={false} className="p-0 overflow-hidden">
            <div className="flex items-center gap-2 px-4 py-3 border-b border-white/[0.06]">
              <div className="w-3 h-3 rounded-full bg-red-500/60" />
              <div className="w-3 h-3 rounded-full bg-yellow-500/60" />
              <div className="w-3 h-3 rounded-full bg-green-500/60" />
              <span className="text-xs text-zinc-500 ml-2">main.go</span>
            </div>
            <div className="p-4 font-mono text-sm leading-relaxed overflow-x-auto">
              <AnimatePresence mode="wait">
                <motion.div
                  key={active}
                  initial={{ opacity: 0, y: 8 }}
                  animate={{ opacity: 1, y: 0 }}
                  exit={{ opacity: 0, y: -8 }}
                  transition={{ duration: 0.2 }}
                >
                  {renderCode(tabs[active].lines)}
                </motion.div>
              </AnimatePresence>
            </div>
          </GlassCard>
        </FadeInCSS>
      </div>
    </section>
  );
}
