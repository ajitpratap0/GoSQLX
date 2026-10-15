/**
 * Brand gradient for a short highlighted phrase inside a solid heading.
 * Uses the semantic brand/accent tokens, so html.light swaps it to the darker
 * light-theme values automatically (both stops meet AA on --bg).
 */
export function GradientText({ children, className = '' }: { children: React.ReactNode; className?: string }) {
  return (
    <span className={`bg-gradient-to-r from-brand to-accent bg-clip-text text-transparent ${className}`}>
      {children}
    </span>
  );
}
