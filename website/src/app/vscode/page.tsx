import type { Metadata } from 'next';
import { VscodeContent } from './VscodeContent';

export const metadata: Metadata = {
  title: 'VS Code Extension',
  description:
    'Real-time SQL validation, formatting, and linting for VS Code. Powered by the GoSQLX parser with multi-dialect support.',
};

export default function VscodePage() {
  return <VscodeContent />;
}
