export function AnimatedCounter({ value, suffix = '', color = 'text-fg' }: { value: number; suffix?: string; color?: string }) {
  // Renders the final value directly: no reset-to-0 flash and nothing hidden pending JS.
  return (
    <span className={`text-3xl sm:text-4xl font-bold tabular-nums ${color}`}>
      {value.toLocaleString('en-US')}{suffix}
    </span>
  );
}
