import type { Metadata } from 'next';
import { pageMeta } from '@/lib/seo';
import { JsonLd } from '@/components/JsonLd';
import { pageJsonLd } from '@/lib/jsonld';

export const metadata: Metadata = pageMeta({
  title: 'Privacy Policy',
  description: 'GoSQLX privacy policy: no cookies, no SQL logging. What the website, playground, MCP server, ChatGPT app and Claude plugin collect, and your rights.',
  path: '/privacy/',
  image: { url: '/opengraph-image', alt: 'GoSQLX' },
});

const jsonLd = pageJsonLd({
  name: 'Privacy Policy',
  description: metadata.description as string,
  path: '/privacy/',
  crumbs: [{ name: 'Privacy Policy', path: '/privacy/' }],
});

const CONTACT_EMAIL = 'privacy@gosqlx.dev';

export default function PrivacyPage() {
  return (
    <>
    <JsonLd data={jsonLd} />
    <div className="min-h-screen section-padding pt-24 pb-24">
      <div className="container-width max-w-3xl prose prose-invert prose-dark">
        <h1>Privacy Policy</h1>
        <p className="lead">
          This policy explains what personal data the GoSQLX website, playground,
          hosted MCP server, ChatGPT app, Claude plugin and VS Code extension
          collect, why, who receives it, and the choices and rights you have.
        </p>
        <p>
          <em>Last updated: October 20, 2026</em>
        </p>

        <h2 id="who-we-are">Who is responsible</h2>
        <p>
          GoSQLX is an open-source project run by its maintainer, Ajit Pratap
          Singh, an individual developer based in India (&ldquo;we&rdquo;,
          &ldquo;us&rdquo;). He is the controller (data fiduciary) for the
          personal data described here and also acts as grievance officer.
          Contact:{' '}
          <a href={`mailto:${CONTACT_EMAIL}`}>{CONTACT_EMAIL}</a>.
        </p>

        <h2 id="website">Website</h2>
        <p>
          The website gosqlx.dev is hosted by Vercel, which, like any web host,
          processes your IP address, browser user agent and the pages you
          request in order to serve the site and protect it from abuse. We set
          no cookies. Your light/dark theme choice is saved in your
          browser&rsquo;s local storage and never leaves your device.
        </p>
        <p>
          We use Vercel Speed Insights to measure page performance (such as
          load time) without cookies and without identifying individual
          visitors. We use Sentry to receive error reports and a sample of
          performance traces from your browser. These contain the error
          message, stack trace, page address and browser and device details.
          IP addresses are not stored, session replay is off, and we do not
          send other personal data to Sentry.
        </p>

        <h2 id="playground">WASM Playground</h2>
        <p>
          SQL in the interactive playground is parsed entirely in your browser
          via WebAssembly; we do not receive your SQL or the results. Error
          reports are not designed to include what you type, but if the
          playground itself fails, an error message sent to Sentry could
          contain a short fragment of it.
        </p>

        <h2 id="mcp-server">Remote MCP Server, ChatGPT App and Claude Plugin</h2>
        <p>
          The hosted MCP server at mcp.gosqlx.dev also powers the GoSQLX
          ChatGPT app and, by default, the GoSQLX Claude plugin. When an AI
          assistant calls a GoSQLX tool, the server receives the tool
          arguments: the SQL text and options such as the dialect or
          indentation. It analyzes them in memory, returns the result and
          keeps nothing. We do not log, store, sell or share SQL text or
          results, and we do not use them to train models.
        </p>
        <p>
          To serve requests, the server holds short-lived state in memory
          that is never written to disk: an MCP session identifier for each
          connected client, deleted after 30 minutes of inactivity, and
          per-IP rate-limit counters, deleted after 10 minutes of inactivity.
          ChatGPT may attach metadata to requests, such as locale, user agent
          or approximate location; the server receives it but does not use,
          log or store it.
        </p>
        <p>
          The server is hosted on Render behind Cloudflare. As our hosting and
          network providers, they process connection data such as IP
          addresses and request times to deliver and protect the service.
          Your conversations with ChatGPT or Claude are handled by OpenAI or
          Anthropic under their own policies; we never see them, only the
          tool calls the assistant makes.
        </p>
        <p>
          You stay in control: the Claude plugin can use a local server
          instead, and the open-source server can be self-hosted so that SQL
          never leaves your infrastructure. Do not send secrets or personal
          data in SQL to any hosted service.
        </p>

        <h2 id="vscode">VS Code Extension</h2>
        <p>
          The GoSQLX VS Code extension runs entirely on your machine and sends
          nothing to us or anyone else. An optional, off-by-default setting
          records anonymous usage statistics (such as command durations and
          error codes, never SQL or file paths) in memory on your machine
          only; they are never transmitted.
        </p>

        <h2 id="purposes">Why we process data and on what basis</h2>
        <ul>
          <li>
            <strong>Delivering the services and returning results</strong>{' '}
            to the request you or your AI assistant made.
          </li>
          <li>
            <strong>Security, abuse prevention and rate limiting</strong>{' '}
            (IP addresses, connection data).
          </li>
          <li>
            <strong>Fixing errors and improving performance</strong> (Sentry,
            Speed Insights).
          </li>
        </ul>
        <p>
          Where the EU or UK GDPR applies, our legal basis is our legitimate
          interest in providing a secure, working free service (Art.&nbsp;6(1)(f)
          GDPR). Under India&rsquo;s Digital Personal Data Protection Act,
          2023, we process the data you voluntarily provide for the specified
          purpose of serving your request, which is a legitimate use under
          Section&nbsp;7 of that Act.
        </p>

        <h2 id="recipients">Who receives data</h2>
        <p>
          We use these service providers, each under its own privacy policy:
          Vercel (website hosting and Speed Insights), Sentry (error and
          performance monitoring), Render (MCP server hosting) and Cloudflare
          (network and security for the MCP server). We do not sell or share
          personal information, including as those terms are defined in the
          California Consumer Privacy Act, and we do not use it for
          advertising.
        </p>

        <h2 id="transfers">International transfers</h2>
        <p>
          These providers process data in the United States and other
          countries. Where data leaves the EEA, UK or India, transfers rely on
          the providers&rsquo; safeguards, such as Standard Contractual
          Clauses or the EU&ndash;U.S. Data Privacy Framework, and are made
          in line with applicable law.
        </p>

        <h2 id="retention">Retention</h2>
        <p>
          We keep SQL and tool results only for the time it takes to process
          a request. Session and rate-limit state is deleted as described
          above. Our providers keep connection logs and error reports for
          their standard retention periods, after which they are deleted.
        </p>

        <h2 id="security">Security</h2>
        <p>
          All traffic to the website and the MCP server is encrypted with TLS.
          The MCP server writes no SQL, results or request data to disk.
        </p>

        <h2 id="rights">Your rights</h2>
        <p>
          Depending on where you live, you may have the right to access,
          correct, erase or receive a copy of your personal data, to object to
          or restrict its processing, to withdraw consent, and to nominate
          someone to exercise your rights. Because we keep almost no personal
          data, there is usually nothing tied to you that we can find, but we
          will answer every request. Email{' '}
          <a href={`mailto:${CONTACT_EMAIL}`}>{CONTACT_EMAIL}</a>; we respond
          within 30 days.
        </p>
        <p>
          If you are unhappy with our response, you may complain to your
          local data protection authority (in the EU or UK) or, in India, to
          the Data Protection Board of India after first raising the
          grievance with us.
        </p>

        <h2 id="children">Children</h2>
        <p>
          GoSQLX is a developer tool and is not directed to children. We do
          not knowingly collect personal data from anyone under 13 (or under
          the age of digital consent where you live, such as 16 in parts of
          the EU, or 18 in India). If you believe a child has sent us
          personal data, contact us and we will delete it.
        </p>

        <h2 id="third-party-links">Third-party links</h2>
        <p>
          The website links to third-party services such as GitHub. These
          services have their own privacy policies, which we encourage you to
          review.
        </p>

        <h2 id="changes">Changes</h2>
        <p>
          We will update this page when our data handling changes and change
          the date above. For material changes we will also note them in the
          project changelog. See also our{' '}
          <a href="/terms/">Terms of Service</a>.
        </p>

        <h2 id="contact">Contact and grievances</h2>
        <p>
          For privacy questions, requests or grievances, email{' '}
          <a href={`mailto:${CONTACT_EMAIL}`}>{CONTACT_EMAIL}</a> (grievance
          officer: Ajit Pratap Singh). For general questions, open an issue
          on our{' '}
          <a
            href="https://github.com/ajitpratap0/GoSQLX/issues"
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
