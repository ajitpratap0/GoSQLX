import type { Metadata } from 'next';
import { pageMeta } from '@/lib/seo';
import { VscodeContent } from './VscodeContent';

export const metadata: Metadata = pageMeta({
  title: 'GoSQLX VS Code Extension: SQL Diagnostics, Formatting & Linting',
  description:
    'Real-time SQL validation, formatting, and linting for VS Code. GoSQLX powers instant diagnostics, auto-formatting, and 30 built-in lint rules with multi-dialect support.',
  path: '/vscode/',
  absolute: true,
});

export default function VscodePage() {
  return <VscodeContent />;
}
