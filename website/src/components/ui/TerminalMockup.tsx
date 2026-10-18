export function TerminalMockup({ command, output }: { command: string; output?: string }) {
  return (
    <div role="region" aria-label="Terminal" className="glass rounded-xl overflow-hidden">
      <div className="flex items-center gap-2 px-4 py-3 border-b border-fg/[0.06]">
        <div aria-hidden="true" className="w-3 h-3 rounded-full bg-danger/60" />
        <div aria-hidden="true" className="w-3 h-3 rounded-full bg-warn/60" />
        <div aria-hidden="true" className="w-3 h-3 rounded-full bg-ok/60" />
        <span className="text-xs text-fg-subtle ml-2">Terminal</span>
      </div>
      <div className="p-4 font-mono text-sm overflow-x-auto">
        <div className="text-fg-muted break-words"><span className="text-brand">$</span> {command}</div>
        {output && <div className="text-fg-subtle mt-1">{output}</div>}
      </div>
    </div>
  );
}
