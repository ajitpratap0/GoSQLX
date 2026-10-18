import fs from 'node:fs';
import path from 'node:path';
import { FadeIn } from '@/components/ui/FadeIn';
import { CodeExamplesTabs, type ApiExample } from '@/components/home/CodeExamplesTabs';

// Each sample is a real `package main` under src/content/api-examples/<id>/main.go,
// so `go build ./...` and `go vet ./...` break CI if the public API drifts from
// what the homepage shows.
const EXAMPLES: { id: string; label: string }[] = [
  { id: 'parse', label: 'Parse' },
  { id: 'format', label: 'Format' },
  { id: 'validate', label: 'Validate' },
  { id: 'lint', label: 'Lint' },
];

const EXAMPLES_DIR = path.join(process.cwd(), 'src', 'content', 'api-examples');

function loadExamples(): ApiExample[] {
  return EXAMPLES.map(({ id, label }) => ({
    id,
    label,
    code: fs.readFileSync(path.join(EXAMPLES_DIR, id, 'main.go'), 'utf-8').trimEnd(),
  }));
}

export function CodeExamples() {
  return (
    <section className="py-20 border-t border-fg/[0.06]">
      <div className="max-w-3xl mx-auto px-4">
        <FadeIn viewport>
          <h2 className="text-3xl font-bold text-fg text-center mb-10">
            Simple, Powerful API
          </h2>
        </FadeIn>
        <FadeIn viewport delay={0.1}>
          <CodeExamplesTabs examples={loadExamples()} />
        </FadeIn>
      </div>
    </section>
  );
}
