import type { Metadata } from 'next';
import { VscodeContent } from './VscodeContent';

export const metadata: Metadata = {
  title: 'VS Code Extension',
  description:
    'Real-time SQL validation, formatting, and linting for VS Code. GoSQLX powers instant diagnostics, auto-formatting, and 10 built-in lint rules with multi-dialect support.',
  alternates: {
    canonical: '/vscode/',
  },
  openGraph: {
    title: 'GoSQLX VS Code Extension — SQL Diagnostics, Formatting & Linting',
    description: 'Real-time SQL validation, formatting, and linting for VS Code. Powered by GoSQLX with multi-dialect support.',
    url: '/vscode/',
  },
};

export default function VscodePage() {
  return <VscodeContent />;
}
