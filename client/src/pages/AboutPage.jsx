import { Card, CardHeader } from '../components/ui/Card.jsx';

function List({ items }) {
  return (
    <ul className="space-y-2 text-sm leading-relaxed text-ink-2">
      {items.map((item) => (
        <li key={item} className="flex gap-2">
          <span aria-hidden="true" className="mt-2 h-1 w-1 shrink-0 rounded-full bg-ink-muted" />
          <span>{item}</span>
        </li>
      ))}
    </ul>
  );
}

export function AboutPage() {
  return (
    <div className="grid gap-4 lg:grid-cols-2">
      <Card>
        <CardHeader
          title="What this tool is for"
          subtitle="Authorized assessment of sites you own or have written permission to test."
        />
        <p className="text-sm leading-relaxed text-ink-2">
          The scanner maps a single origin, inventories its endpoints, and looks for evidence of three common classes
          of flaw. It reports what it observed and how it observed it, so a human can confirm the finding. It is not
          an exploitation framework, and every finding it produces should be treated as a lead rather than a verdict.
        </p>
      </Card>

      <Card>
        <CardHeader title="How the checks stay safe" />
        <List
          items={[
            'XSS: a random canary plus the four characters " \' < > . The scanner measures which characters survive unencoded and in which HTML context. No script is ever executed.',
            'SQL injection: a single quote to look for database errors, and quote-balanced always-true / always-false conditions compared against a baseline. Read-only - no UNION, no stacked statements, no data is selected, modified or extracted.',
            'Path traversal: probes use random names that cannot exist. The scanner never requests /etc/passwd, configuration files or any other sensitive path.',
            'Passive checks read responses the crawler already fetched - they cost no extra requests.',
            'Forms with password fields are never submitted, and POST forms stay opt-in because a POST can create data.',
            'Parameters whose names look like tokens, sessions, keys or passwords are skipped entirely.',
          ]}
        />
      </Card>

      <Card>
        <CardHeader title="Limits the scanner enforces on itself" />
        <List
          items={[
            'One origin per scan. Off-scope links are inventoried, never requested, and redirects are re-validated at every hop.',
            'Requests to localhost, private ranges, link-local addresses and cloud metadata endpoints are refused - the DNS answer is checked again at connect time, so a rebinding attempt fails too.',
            'Page count, crawl depth, request budget, response size, scan duration and concurrency are all capped server-side; the dashboard cannot raise them past those caps.',
            'robots.txt is honoured by default, including Crawl-delay.',
            'The scanner identifies itself in the User-Agent so site owners can recognise its traffic in their logs.',
          ]}
        />
      </Card>

      <Card>
        <CardHeader title="Before you scan" />
        <List
          items={[
            'Confirm in writing who owns the target and that testing is permitted, including the time window.',
            'Prefer a staging environment. Even paced, read-only traffic is traffic, and error-triggering probes appear in production logs and alerting.',
            'Shared hosting, CDNs and WAFs mean your target may not be the only thing you affect. Check before you start.',
            'Treat results as sensitive: they describe how to attack the site. Scan history is stored in this browser only.',
            'Confirm every finding manually before reporting it. The scanner labels its confidence for exactly this reason.',
          ]}
        />
      </Card>
    </div>
  );
}
