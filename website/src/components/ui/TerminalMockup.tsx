export function TerminalMockup({ command, output }: { command: string; output?: string }) {
  return (
    <div role="region" aria-label="Terminal" className="glass rounded-xl overflow-hidden">
      <div className="flex items-center gap-2 px-4 py-3 border-b border-white/[0.06]">
        <div aria-hidden="true" className="w-3 h-3 rounded-full bg-red-500/60" />
        <div aria-hidden="true" className="w-3 h-3 rounded-full bg-yellow-500/60" />
        <div aria-hidden="true" className="w-3 h-3 rounded-full bg-green-500/60" />
        <span className="text-xs text-zinc-500 ml-2">Terminal</span>
      </div>
      <div className="p-4 font-mono text-sm overflow-x-auto">
        <div className="text-zinc-400 break-words"><span className="text-accent-green">$</span> {command}</div>
        {output && <div className="text-zinc-500 mt-1">{output}</div>}
      </div>
    </div>
  );
}
