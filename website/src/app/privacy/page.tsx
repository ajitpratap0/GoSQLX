import type { Metadata } from 'next';
import { pageMeta } from '@/lib/seo';
import { JsonLd } from '@/components/JsonLd';
import { pageJsonLd } from '@/lib/jsonld';

export const metadata: Metadata = pageMeta({
  title: 'Privacy Policy',
  description: 'GoSQLX privacy policy: no tracking, no telemetry and no query logging. What the website, playground, hosted MCP server, ChatGPT app and Claude plugin do and do not collect.',
  path: '/privacy/',
  image: { url: '/opengraph-image', alt: 'GoSQLX' },
});

const jsonLd = pageJsonLd({
  name: 'Privacy Policy',
  description: metadata.description as string,
  path: '/privacy/',
  crumbs: [{ name: 'Privacy Policy', path: '/privacy/' }],
});

export default function PrivacyPage() {
  return (
    <>
    <JsonLd data={jsonLd} />
    <div className="min-h-screen section-padding pt-24 pb-24">
      <div className="container-width max-w-3xl prose prose-invert prose-dark">
        <h1>Privacy Policy</h1>
        <p className="lead">
          GoSQLX is committed to user privacy. This policy explains what data is
          (and is not) collected across our website, tools, and services.
        </p>

        <p>
          <em>Last updated: October 20, 2026</em>
        </p>

        <h2>Website</h2>
        <p>
          The GoSQLX website is a static site. We use Vercel Speed Insights, a
          privacy-friendly service that measures page performance (such as load
          time) without cookies and without tracking individual users. We also
          use Sentry to receive error reports when something breaks in your
          browser; these contain the error message, stack trace, and browser and
          page details, but we do not enable session replay, and we do not
          collect IP addresses or other personal data through it.
        </p>

        <h2>WASM Playground</h2>
        <p>
          All SQL parsing in the interactive playground runs entirely in your
          browser via WebAssembly. No queries, SQL text, or parsing results are
          ever sent to our servers.
        </p>

        <h2>Remote MCP Server, ChatGPT App and Claude Plugin</h2>
        <p>
          The hosted MCP server at mcp.gosqlx.dev also powers the GoSQLX
          ChatGPT app and, by default, the GoSQLX Claude plugin. When an AI
          assistant calls a GoSQLX tool, the server receives the tool
          arguments: the SQL text and options such as the dialect or
          indentation. It analyzes them in memory, returns the result and
          keeps nothing. It does not log, store, sell or share SQL text or
          results, and it does not use them to train models.
        </p>
        <p>
          To serve requests, the server holds short-lived, in-memory state
          that is never written to disk: an MCP session identifier for each
          connected client, cleared after 30 minutes of inactivity, and per-IP
          rate-limit counters, cleared after 10 minutes of inactivity. Request metadata that ChatGPT may attach, such as
          locale, user agent or approximate location, is ignored.
        </p>
        <p>
          The server is hosted on Render behind Cloudflare. As our network and
          hosting providers, they process connection data such as IP
          addresses and request times to deliver and protect the service,
          under their own privacy policies. Your conversations with ChatGPT or
          Claude are handled by OpenAI or Anthropic under their policies; we
          never see them, only the tool calls the assistant makes.
        </p>
        <p>
          You stay in control: the plugin can run against a local server, and
          the open-source server can be self-hosted so that SQL never leaves
          your infrastructure. Do not send secrets or personal data in SQL to
          any hosted service.
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

        <h2>Changes</h2>
        <p>
          We will update this page when our data handling changes; the date
          above shows the latest revision. See also our{' '}
          <a href="/terms/">Terms of Service</a>.
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
    </div>
    </>
  );
}
