export function VersionBadge({ version }: { version: string }) {
  return (
    <span className="inline-block bg-accent-indigo/10 border border-accent-indigo/20 rounded-full px-3.5 py-1 text-xs text-accent-indigo/80">
      {version}
    </span>
  );
}
