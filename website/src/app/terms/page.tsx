import type { Metadata } from 'next';
import { pageMeta } from '@/lib/seo';
import { JsonLd } from '@/components/JsonLd';
import { pageJsonLd } from '@/lib/jsonld';

export const metadata: Metadata = pageMeta({
  title: 'Terms of Service',
  description: 'Terms for using the GoSQLX website, playground, hosted MCP server, ChatGPT app and Claude plugin: free, as-is, read-only SQL analysis with fair-use limits.',
  path: '/terms/',
  image: { url: '/opengraph-image', alt: 'GoSQLX' },
});

const jsonLd = pageJsonLd({
  name: 'Terms of Service',
  description: metadata.description as string,
  path: '/terms/',
  crumbs: [{ name: 'Terms of Service', path: '/terms/' }],
});

export default function TermsPage() {
  return (
    <>
    <JsonLd data={jsonLd} />
    <div className="min-h-screen section-padding pt-24 pb-24">
      <div className="container-width max-w-3xl prose prose-invert prose-dark">
        <h1>Terms of Service</h1>
        <p className="lead">
          These terms cover the GoSQLX hosted services: the gosqlx.dev website
          and playground, the remote MCP server at mcp.gosqlx.dev, the GoSQLX
          ChatGPT app and the GoSQLX Claude plugin (together, the
          &ldquo;Services&rdquo;). By using the Services you agree to these
          terms.
        </p>
        <p>
          <em>Last updated: October 20, 2026</em>
        </p>

        <h2>The software</h2>
        <p>
          The GoSQLX source code, CLI, libraries, VS Code extension and MCP
          server binary are open source under the{' '}
          <a
            href="https://github.com/ajitpratap0/GoSQLX/blob/main/LICENSE"
            target="_blank"
            rel="noopener noreferrer"
          >
            Apache License 2.0
          </a>
          . That license, not these terms, governs your use, modification and
          distribution of the software, including when you run it yourself.
        </p>

        <h2>What the Services do</h2>
        <p>
          The Services parse, validate, format, lint and scan SQL text that you
          (or an AI assistant acting for you) send to them, and return the
          analysis. They never connect to a database and never execute SQL.
          The Services are free and require no account.
        </p>

        <h2>Acceptable use</h2>
        <p>You agree not to:</p>
        <ul>
          <li>
            send secrets, credentials, or personal or confidential data in SQL
            you submit to a hosted Service (self-host the open-source server
            for sensitive SQL);
          </li>
          <li>
            attempt to overload, disrupt, probe for vulnerabilities in or get
            around the rate limits of the Services, or access them by automated
            means at a volume beyond normal interactive or CI use;
          </li>
          <li>
            use the Services to break the law or to infringe anyone&rsquo;s
            rights.
          </li>
        </ul>
        <p>
          We may rate-limit, block or stop serving traffic that breaks these
          rules or threatens the availability of the Services for others.
          Report security issues privately as described in our{' '}
          <a
            href="https://github.com/ajitpratap0/GoSQLX/blob/main/SECURITY.md"
            target="_blank"
            rel="noopener noreferrer"
          >
            security policy
          </a>
          .
        </p>

        <h2>Your content</h2>
        <p>
          You keep all rights to the SQL you submit. You grant us only the
          permission needed to process it and return a result. How the hosted
          Services handle your data is described in our{' '}
          <a href="/privacy/">Privacy Policy</a>.
        </p>

        <h2>AI assistants</h2>
        <p>
          When you use GoSQLX through ChatGPT, Claude or another AI assistant,
          your use of that assistant is governed by its provider&rsquo;s own
          terms and privacy policy. The assistant decides when to call GoSQLX
          tools and what to tell you about the results; we are not responsible
          for the assistant&rsquo;s output.
        </p>

        <h2>No warranty</h2>
        <p>
          The Services are provided &ldquo;as is&rdquo; and &ldquo;as
          available&rdquo;, without warranties of any kind, express or implied,
          including merchantability, fitness for a particular purpose and
          non-infringement. Analysis results, including security findings and
          lint suggestions, may be incomplete or wrong. A clean security scan
          does not mean SQL is safe. Review results before you rely on them.
        </p>

        <h2>Availability and changes</h2>
        <p>
          The hosted Services are run on a best-effort basis with no uptime
          commitment. We may change, suspend or discontinue any of them at any
          time. We may update these terms; the date above shows the latest
          revision, and continued use after a change means you accept it.
        </p>

        <h2>Limitation of liability</h2>
        <p>
          To the maximum extent permitted by law, the GoSQLX authors and
          maintainers are not liable for any indirect, incidental, special,
          consequential or punitive damages, or for any loss of data, profits
          or business, arising from your use of or inability to use the
          Services.
        </p>

        <h2>Contact and support</h2>
        <p>
          For questions about these terms or help with the Services, open an
          issue on{' '}
          <a
            href="https://github.com/ajitpratap0/GoSQLX/issues"
            target="_blank"
            rel="noopener noreferrer"
          >
            GitHub Issues
          </a>{' '}
          or start a thread in{' '}
          <a
            href="https://github.com/ajitpratap0/GoSQLX/discussions"
            target="_blank"
            rel="noopener noreferrer"
          >
            GitHub Discussions
          </a>
          .
        </p>
      </div>
    </div>
    </>
  );
}
