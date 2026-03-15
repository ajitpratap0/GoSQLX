import type { Metadata } from 'next';

export const metadata: Metadata = {
  title: 'Privacy Policy',
  description: 'GoSQLX privacy policy. No tracking, no telemetry, no query logging.',
};

export default function PrivacyPage() {
  return (
    <main className="min-h-screen section-padding pt-24 pb-24">
      <div className="container-width max-w-3xl prose prose-invert">
        <h1>Privacy Policy</h1>
        <p className="lead">
          GoSQLX is committed to user privacy. This policy explains what data is
          (and is not) collected across our website, tools, and services.
        </p>

        <h2>Website</h2>
        <p>
          The GoSQLX website is a static site. We use Vercel Analytics, a
          privacy-friendly analytics service that does not use cookies and does
          not track individual users. No personal data is collected or stored.
        </p>

        <h2>WASM Playground</h2>
        <p>
          All SQL parsing in the interactive playground runs entirely in your
          browser via WebAssembly. No queries, SQL text, or parsing results are
          ever sent to our servers.
        </p>

        <h2>Remote MCP Server</h2>
        <p>
          The hosted MCP server is stateless. It does not log, store, or
          transmit any SQL queries it processes. IP-based rate-limit counters
          are held in memory and automatically cleared after 10 minutes.
        </p>

        <h2>VS Code Extension</h2>
        <p>
          The GoSQLX VS Code extension runs entirely on your local machine. It
          does not send telemetry, usage data, or any SQL content to external
          servers.
        </p>

        <h2>Third-party Links</h2>
        <p>
          The website links to third-party services such as GitHub and Render.
          These services have their own privacy policies. We encourage you to
          review them independently.
        </p>

        <h2>Contact</h2>
        <p>
          If you have questions about this privacy policy, please open an issue
          on our{' '}
          <a
            href="https://github.com/ajitpratap0/GoSQLX"
            target="_blank"
            rel="noopener noreferrer"
          >
            GitHub repository
          </a>
          .
        </p>
      </div>
    </main>
  );
}
