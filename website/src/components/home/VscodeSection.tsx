'use client';

import { FadeIn } from '@/components/ui/FadeIn';
import { GlassCard } from '@/components/ui/GlassCard';
import { Button } from '@/components/ui/Button';

export function VscodeSection() {
  return (
    <section className="py-20 border-t border-white/[0.06]">
      <div className="max-w-6xl mx-auto px-4">
        <div className="flex flex-col md:flex-row items-center gap-10">
          {/* Left: Copy */}
          <div className="md:w-1/2">
            <FadeIn>
              <h2 className="text-3xl font-bold text-white mb-4">
                IDE Integration
              </h2>
              <p className="text-zinc-300 mb-6 max-w-md">
                Real-time SQL validation, formatting, and linting in VS Code. Catch errors as you type with full multi-dialect support.
              </p>
              <Button
                href="https://marketplace.visualstudio.com/items?itemName=ajitpratap0.gosqlx"
                variant="primary"
                external
              >
                <svg className="w-4 h-4" viewBox="0 0 24 24" fill="currentColor">
                  <path d="M17.583.063a1.5 1.5 0 0 1 1.342.825l4.95 10.05a1.5 1.5 0 0 1 0 1.324l-4.95 10.05a1.5 1.5 0 0 1-2.007.668L.463 15.208A1.5 1.5 0 0 1 0 13.917v-3.834a1.5 1.5 0 0 1 .463-1.291L16.918.73a1.5 1.5 0 0 1 .665-.668Z" />
                </svg>
                Install Extension
              </Button>
            </FadeIn>
          </div>

          {/* Right: VS Code Mockup */}
          <div className="md:w-1/2 w-full">
            <FadeIn delay={0.2}>
              <GlassCard hover={false} className="p-0 overflow-hidden">
                {/* Title bar */}
                <div className="flex items-center gap-2 px-4 py-3 border-b border-white/[0.06] bg-white/[0.02]">
                  <div className="w-3 h-3 rounded-full bg-red-500/60" />
                  <div className="w-3 h-3 rounded-full bg-yellow-500/60" />
                  <div className="w-3 h-3 rounded-full bg-green-500/60" />
                  <span className="text-xs text-zinc-500 ml-2">query.sql — GoSQLX</span>
                </div>
                {/* Editor content */}
                <div className="p-4 font-mono text-sm leading-relaxed">
                  <div className="flex">
                    <span className="w-8 text-right text-zinc-600 select-none mr-4">1</span>
                    <span>
                      <span className="text-accent-indigo">SELECT</span>
                      <span className="text-zinc-300"> u.id, u.name, u.email</span>
                    </span>
                  </div>
                  <div className="flex">
                    <span className="w-8 text-right text-zinc-600 select-none mr-4">2</span>
                    <span>
                      <span className="text-accent-indigo">FROM</span>
                      <span className="text-accent-orange"> users</span>
                      <span className="text-zinc-300"> u</span>
                    </span>
                  </div>
                  <div className="flex">
                    <span className="w-8 text-right text-zinc-600 select-none mr-4">3</span>
                    <span>
                      <span className="text-accent-indigo">JOIN</span>
                      <span className="text-accent-orange"> orders</span>
                      <span className="text-zinc-300"> o </span>
                      <span className="text-accent-indigo">ON</span>
                      <span className="text-zinc-300"> o.user_id = u.id</span>
                    </span>
                  </div>
                  <div className="flex">
                    <span className="w-8 text-right text-zinc-600 select-none mr-4">4</span>
                    <span>
                      <span className="text-accent-indigo">WHERE</span>
                      <span className="text-zinc-300"> u.active = </span>
                      <span className="text-accent-purple">true</span>
                    </span>
                  </div>
                  <div className="flex">
                    <span className="w-8 text-right text-zinc-600 select-none mr-4">5</span>
                    <span>
                      <span className="text-accent-indigo">ORDER BY</span>
                      <span className="text-zinc-300"> u.name </span>
                      <span className="text-accent-indigo">ASC</span>
                      <span className="text-zinc-300">;</span>
                    </span>
                  </div>
                </div>
                {/* Status bar */}
                <div className="flex items-center justify-between px-4 py-2 border-t border-white/[0.06] bg-white/[0.02] text-xs">
                  <div className="flex items-center gap-2">
                    <span className="flex items-center gap-1 text-accent-green">
                      <svg className="w-3 h-3" fill="currentColor" viewBox="0 0 20 20">
                        <path fillRule="evenodd" d="M10 18a8 8 0 1 0 0-16 8 8 0 0 0 0 16Zm3.857-9.809a.75.75 0 0 0-1.214-.882l-3.483 4.79-1.88-1.88a.75.75 0 1 0-1.06 1.061l2.5 2.5a.75.75 0 0 0 1.137-.089l4-5.5Z" clipRule="evenodd" />
                      </svg>
                      Valid SQL
                    </span>
                    <span className="text-zinc-500">|</span>
                    <span className="text-zinc-500">PostgreSQL</span>
                  </div>
                  <span className="text-zinc-500">0 issues</span>
                </div>
              </GlassCard>
            </FadeIn>
          </div>
        </div>
      </div>
    </section>
  );
}
