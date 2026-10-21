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

const CONTACT_EMAIL = 'privacy@gosqlx.dev';

export default function TermsPage() {
  return (
    <>
    <JsonLd data={jsonLd} />
    <div className="min-h-screen section-padding pt-24 pb-24">
      <div className="container-width max-w-3xl prose prose-invert prose-dark">
        <h1>Terms of Service</h1>
        <p className="lead">
          These terms are an agreement between you and Ajit Pratap Singh, the
          individual developer who maintains GoSQLX (&ldquo;we&rdquo;,
          &ldquo;us&rdquo;). They cover the GoSQLX hosted services: the
          gosqlx.dev website and playground, the remote MCP server at
          mcp.gosqlx.dev, the GoSQLX ChatGPT app and the GoSQLX Claude plugin
          (together, the &ldquo;Services&rdquo;). By using the Services you
          agree to these terms. If you do not agree, do not use them.
        </p>
        <p>
          <em>Last updated: October 20, 2026</em>
        </p>

        <h2 id="software">The software</h2>
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
          As the license states, it grants no rights in the GoSQLX name or
          logo, which you may use only to refer to the project accurately.
        </p>

        <h2 id="services">What the Services do</h2>
        <p>
          The Services parse, validate, format, lint and scan SQL text that you
          (or an AI assistant acting for you) send to them, and return the
          analysis. They never connect to a database and never execute SQL.
          The Services are free and require no account.
        </p>

        <h2 id="eligibility">Eligibility</h2>
        <p>
          You must be at least 18, or the age of majority where you live, or
          use the Services with the consent and supervision of a parent or
          guardian. If you use the Services for an organization, you confirm
          that you may accept these terms for it.
        </p>

        <h2 id="acceptable-use">Acceptable use</h2>
        <p>
          Use through AI assistants and integrations, including the GoSQLX
          ChatGPT app and Claude plugin, and reasonable automated use such as
          CI checks, is permitted. You agree not to:
        </p>
        <ul>
          <li>
            send secrets, credentials, or personal or confidential data in SQL
            you submit to a hosted Service (self-host the open-source server
            for sensitive SQL);
          </li>
          <li>
            attempt to overload, disrupt, probe for vulnerabilities in or get
            around the rate limits of the Services, or send traffic at a
            volume that degrades them for others;
          </li>
          <li>
            use the Services to break the law or to infringe anyone&rsquo;s
            rights.
          </li>
        </ul>
        <p>
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

        <h2 id="your-content">Your content</h2>
        <p>
          You keep all rights to the SQL you submit, and you are responsible
          for having the right to submit it. You grant us only the permission
          needed to process it and return a result. How the Services handle
          your data is described in our{' '}
          <a href="/privacy/">Privacy Policy</a>.
        </p>

        <h2 id="ai-assistants">AI assistants and third-party services</h2>
        <p>
          When you use GoSQLX through ChatGPT, Claude or another AI assistant,
          your use of that assistant is governed by its provider&rsquo;s own
          terms and privacy policy. The assistant decides when to call GoSQLX
          tools and what to tell you about the results; we are not responsible
          for the assistant&rsquo;s output or for third-party services.
        </p>

        <h2 id="no-warranty">No warranty</h2>
        <p className="uppercase">
          <strong>
            The Services are provided &ldquo;as is&rdquo; and &ldquo;as
            available&rdquo;, without warranties of any kind, express or
            implied, including merchantability, fitness for a particular
            purpose, accuracy and non-infringement, to the fullest extent
            permitted by law.
          </strong>
        </p>
        <p>
          Analysis results, including security findings and lint suggestions,
          may be incomplete or wrong. A clean security scan does not mean SQL
          is safe, and the Services are not a substitute for professional
          security or code review. You are responsible for reviewing results
          before you rely on them.
        </p>

        <h2 id="liability">Limitation of liability</h2>
        <p className="uppercase">
          <strong>
            To the fullest extent permitted by law, we are not liable for any
            indirect, incidental, special, consequential, exemplary or
            punitive damages, or for any loss of data, profits, revenue or
            business, arising from or related to the Services, even if
            advised of the possibility. Our total liability for all claims
            relating to the Services is limited to the greater of the amount
            you paid us for them in the 12 months before the claim (which,
            for these free Services, is zero) and USD 100.
          </strong>
        </p>
        <p>
          Nothing in these terms excludes or limits liability that cannot be
          excluded or limited by law, including liability for death or
          personal injury caused by negligence, for fraud, or for gross
          negligence or wilful misconduct, or any rights you have as a
          consumer under mandatory law.
        </p>

        <h2 id="indemnity">Indemnity</h2>
        <p>
          To the extent permitted by law, you will compensate us for
          reasonable losses and costs arising from third-party claims caused
          by your breach of the acceptable-use rules above or your misuse of
          the Services.
        </p>

        <h2 id="suspension">Suspension and termination</h2>
        <p>
          We may rate-limit, suspend or end access to the Services for anyone
          who breaks these terms or threatens their availability for others,
          and we may change, suspend or discontinue any Service at any time.
          The hosted Services are run on a best-effort basis with no uptime
          commitment. The sections on your content, no warranty, limitation of
          liability, indemnity and governing law survive termination.
        </p>

        <h2 id="changes">Changes to these terms</h2>
        <p>
          We may update these terms and will change the date above. Material
          changes take effect 14 days after they are posted, and we will note
          them in the project changelog; other changes take effect when
          posted. If you keep using the Services after a change takes effect,
          the updated terms apply.
        </p>

        <h2 id="governing-law">Governing law and disputes</h2>
        <p>
          These terms are governed by the laws of India. The courts at
          Bengaluru, Karnataka have exclusive jurisdiction over disputes
          arising from them, except that if you use the Services as a
          consumer, you may also bring proceedings in, and keep the
          protection of the mandatory laws of, the country where you live.
          Before starting proceedings, please contact us so we can try to
          resolve the issue informally.
        </p>

        <h2 id="general">General</h2>
        <p>
          These terms and the Privacy Policy are the entire agreement between
          you and us about the Services. If any provision is held
          unenforceable, the rest remain in effect. Our failure to enforce a
          provision is not a waiver. You may not transfer these terms; we may
          transfer them to someone who takes over the project. If a
          translation conflicts with the English version, the English
          version controls.
        </p>

        <h2 id="contact">Contact and support</h2>
        <p>
          For legal notices or questions about these terms, email{' '}
          <a href={`mailto:${CONTACT_EMAIL}`}>{CONTACT_EMAIL}</a>. For help
          with the Services, open an issue on{' '}
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
