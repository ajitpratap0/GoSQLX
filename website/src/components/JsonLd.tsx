/**
 * Renders a JSON-LD structured-data script. Data passed in is always built from
 * static, first-party values (never user input). "<" is escaped so the payload
 * can never close the script tag.
 */
export function JsonLd({ data }: { data: Record<string, unknown> | Array<Record<string, unknown>> }) {
  return (
    <script
      type="application/ld+json"
      suppressHydrationWarning
      dangerouslySetInnerHTML={{ __html: JSON.stringify(data).replace(/</g, '\\u003c') }}
    />
  );
}
