import type { Metadata } from 'next';
import PlaygroundLoader from './PlaygroundLoader';

export const metadata: Metadata = {
  title: 'SQL Playground',
  description: 'Interactive SQL playground - parse, format, lint, and analyze SQL in the browser',
};

export default function PlaygroundPage() {
  return (
    <div className="h-[calc(100vh-64px)]">
      <PlaygroundLoader />
    </div>
  );
}
