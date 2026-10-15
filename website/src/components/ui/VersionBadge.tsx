export function VersionBadge({ version }: { version: string }) {
  return (
    <span className="inline-block bg-accent/10 border border-accent/30 rounded-full px-3.5 py-1 text-xs text-accent">
      {version}
    </span>
  );
}
