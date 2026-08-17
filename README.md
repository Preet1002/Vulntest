# Web Vulnerability Scanner

An authorized web vulnerability scanner: a Node/Express backend that crawls a
single approved origin and runs conservative, read-only checks against what it
finds, and a React dashboard that shows discovered endpoints, findings and
evidence in real time.

**This is an assessment tool, not an exploitation framework.** It gathers
evidence that a vulnerability may exist and explains how it reached that
conclusion. Confirming a finding is a manual step you take afterwards.

> Scan only what you own or have written permission to test. The API refuses any
> scan request that does not carry an explicit authorization confirmation.

---

## Contents

- [Quick start](#quick-start)
- [Architecture](#architecture)
- [Project structure](#project-structure)
- [How the checks work](#how-the-checks-work)
- [Safety model](#safety-model)
- [Backend API](#backend-api)
- [Scan configuration](#scan-configuration)
- [Storage](#storage)
- [Testing](#testing)
- [Trying it against the bundled test app](#trying-it-against-the-bundled-test-app)
- [Troubleshooting](#troubleshooting)

---

## Quick start

Requires **Node.js 18.17+** (developed on Node 22).

```bash
# 1. install both workspaces
npm run install:all
# equivalent to:
#   cd server && npm install
#   cd client && npm install

# 2. start the backend (terminal 1) - http://127.0.0.1:4000
npm run dev:server

# 3. start the dashboard (terminal 2) - http://localhost:5173
npm run dev:client
```

Open <http://localhost:5173>, enter a URL you are authorized to test, tick the
authorization checkbox and press **Start scan**.

The dashboard talks to the backend through Vite's dev proxy, so every browser
request is same-origin and Server-Sent Events work without CORS configuration.

### Production build

```bash
npm run build:client     # static assets in client/dist
npm run start:server     # node server/src/server.js
```

Serve `client/dist` from any static host and point it at the API with
`VITE_API_BASE` at build time (default `/api`), or keep a reverse proxy that
forwards `/api` to the backend.

### Configuration

Copy `server/.env.example` to `server/.env` and adjust as needed. The server runs
with sensible defaults if no `.env` exists.

| Variable | Default | Purpose |
|---|---|---|
| `PORT` / `HOST` | `4000` / `127.0.0.1` | API bind address |
| `CORS_ORIGIN` | `http://localhost:5173,…` | browser origins allowed to call the API |
| `SCAN_RETENTION` | `25` | finished scans kept in server memory |
| `MAX_CONCURRENT_SCANS` | `2` | scans allowed to run at once |
| `SCANNER_USER_AGENT` | `VulnScanner/1.0 (…)` | how the scanner identifies itself |
| `API_RATE_LIMIT` / `SCAN_RATE_LIMIT` | `300/min`, `10/5min` | API-side rate limits |
| `ALLOW_PRIVATE_TARGETS` | `false` | **see [Safety model](#safety-model)** |

---

## Architecture

```text
React dashboard (Vite, Tailwind, Recharts)
        |  REST for actions and results
        |  Server-Sent Events for live progress
        v
Express API  (routes/, middleware/)
        |
Scan manager  (services/scanManager.js)
        |            creates a ScanContext per scan:
        |            policy + HTTP client + limits + findings
        +--> Crawler   (crawler/)   BFS queue, depth/page caps, robots.txt
        +--> Scanner   (scanner/)   xss.js · sqli.js · pathTraversal.js · passive.js
        |
HTTP request layer  (services/httpClient.js)
        |   one choke point: timeouts, rate limiting, scope policy,
        |   SSRF guard, response size caps, redirect re-validation
        v
Authorized target
```

Nothing above the HTTP layer may call `axios` or `fetch` directly. Every
outbound request passes the same checks, which is what keeps the backend from
behaving like a general-purpose URL fetcher.

A scan runs in three phases, reported as progress:

1. **Crawl** (0–55%) — fetch pages, extract links, forms, parameters and script
   references; passive checks run on each response at no extra request cost.
2. **Discovery** (55–60%) — read same-origin scripts for API routes and verify
   the candidates that look safe to request.
3. **Active testing** (60–100%) — run the enabled detection modules against each
   discovered parameter.

---

## Project structure

```text
vulnerability-scanner/
├── package.json                    convenience scripts for both workspaces
├── README.md
├── testbed/
│   └── vulnerable-app.js           intentionally vulnerable localhost app
│
├── client/
│   ├── index.html                  entry document; applies the stored theme pre-paint
│   ├── vite.config.js              dev server + /api proxy (SSE-safe)
│   └── src/
│       ├── main.jsx                React root, router and theme provider
│       ├── App.jsx                 layout and routes
│       ├── index.css               Tailwind v4 import + design tokens (light/dark)
│       ├── components/
│       │   ├── Header.jsx          title, navigation, theme switch
│       │   ├── ScanLauncher.jsx    target input, authorization, start/stop
│       │   ├── ConfigDialog.jsx    scan configuration modal
│       │   ├── SummaryCards.jsx    stat tiles (pages, endpoints, severities)
│       │   ├── ProgressPanel.jsx   progress bar, counters, current URL
│       │   ├── ActivityLog.jsx     rolling scanner log
│       │   ├── FindingsTable.jsx   filterable vulnerability table
│       │   ├── FindingDetail.jsx   slide-over with evidence and remediation
│       │   ├── EndpointExplorer.jsx searchable endpoint inventory
│       │   ├── HistoryTable.jsx    stored scans
│       │   ├── ScanResults.jsx     results view shared by live and stored scans
│       │   ├── charts/             SeverityChart · TypeChart · StatusCodeChart
│       │   └── ui/                 Card · Button · Badge · EmptyState
│       ├── pages/                  DashboardPage · HistoryPage · ScanViewPage · AboutPage
│       ├── hooks/
│       │   ├── useScanStream.js    SSE subscription with polling fallback
│       │   ├── useScanHistory.js   localStorage-backed history
│       │   └── useTheme.jsx        theme state and chart palette
│       ├── services/api.js         axios client for the scanner API
│       └── utils/                  severity · palette · format · storage
│
└── server/
    ├── .env.example
    ├── test/                       34 tests (node --test)
    │   ├── fixtures/fakeSite.js    in-memory vulnerable site + fake HTTP client
    │   ├── scan.test.js            crawler + detection, end to end
    │   ├── security.test.js        SSRF rules, scope policy, URL handling
    │   └── api.test.js             API validation and rejection paths
    └── src/
        ├── server.js               process entry, graceful shutdown
        ├── app.js                  Express app: helmet, CORS, routes
        ├── config/index.js         defaults, hard limits, config clamping
        ├── routes/scans.js         scan API + SSE stream + /config
        ├── middleware/             errorHandler · rateLimit · validateScanRequest
        ├── security/
        │   ├── ipRules.js          private/loopback/metadata IP classification
        │   ├── ssrfGuard.js        pre-flight checks + connect-time DNS hook
        │   └── targetPolicy.js     same-origin scope enforcement
        ├── services/
        │   ├── httpClient.js       the single outbound HTTP layer
        │   ├── rateLimiter.js      concurrency + inter-request delay
        │   ├── robots.js           robots.txt parsing and matching
        │   ├── scanStore.js        in-memory scans + SSE event bus
        │   ├── scanContext.js      per-scan state, findings, progress
        │   └── scanManager.js      scan lifecycle
        ├── crawler/
        │   ├── crawler.js          bounded BFS crawl
        │   └── parser.js           HTML/JS extraction (cheerio)
        ├── scanner/
        │   ├── index.js            active-scan orchestration
        │   ├── injectionPoints.js  (endpoint, parameter) pairs to test
        │   ├── xss.js              reflection and encoding analysis
        │   ├── sqli.js             error-based and boolean-based checks
        │   ├── pathTraversal.js    error-based and behavioural checks
        │   ├── passive.js          headers, cookies, error disclosure
        │   └── signatures.js       shared response fingerprints
        └── utils/                  url · text · ids · errors · logger
```

---

## How the checks work

Every module reports `severity` **and** `confidence`, and describes the evidence
it used. Nothing is labelled "confirmed" on the strength of a single signal.

### Reflected XSS (`scanner/xss.js`)

1. Send a random canary (`xss<random>`) and check whether it comes back at all.
   If not, stop — no requests wasted.
2. Send the canary followed by the four markup-significant characters `"'<>`.
3. Locate every reflection, work out its context (HTML text, attribute — quoted
   or not, URL attribute, event handler, `<script>`, comment) and record which
   of those characters survived **unencoded**.

| Evidence | Result |
|---|---|
| The quote delimiting the attribute or JS string survives | High severity, **High** confidence |
| `<` and `>` both survive in HTML text | High severity, **High** confidence |
| Characters survive but breakout is less certain | High/Medium severity, **Medium** confidence |
| Value reflected, all characters encoded | reported as `Reflected Parameter Value`, **Info** — explicitly *not* XSS |

No script payload is ever sent, and nothing executes. The finding says what was
reflected and how it was encoded; you confirm exploitability yourself.

### SQL injection (`scanner/sqli.js`)

Two independent signals, both read-only:

- **Error-based** — a single quote produces a database error the original
  request did not. A balanced pair of quotes (`''`) is then sent as a control: if
  that clears the error, confidence is High; if not, Medium.
- **Boolean-based** — with no error available, the baseline is measured twice to
  establish how noisy the page is. A benign control value (`<value>zqx9`) must
  change nothing; then a quote-balanced always-true condition must render the
  baseline page while an always-false condition renders a measurably different
  one. Pages too dynamic to compare are skipped rather than guessed at.

A bare HTTP 500 is never enough on its own: it is reported at **Low** confidence
only when the quote triggers it and the benign control does not.

There are no UNION queries, no stacked statements, no comment truncation, no time
delays, and no attempt to read, write or enumerate data.

### Path traversal (`scanner/pathTraversal.js`)

Only parameters that look path-related are tested, and **no sensitive file is
ever requested** — no `/etc/passwd`, no config files.

- **Error-based** — probe a random name behind `../`. A filesystem error proves
  the value reaches a file operation; if the error discloses an absolute path,
  confidence rises to Medium.
- **Behavioural** — send `<random>/<file>` (a directory that cannot exist) and
  confirm the page breaks, then send `<random>/../<file>`. If that returns
  exactly the baseline, the server resolved the traversal itself.

### Passive checks (`scanner/passive.js`)

Run on responses the crawler already fetched, so they cost no extra requests:
missing CSP / clickjacking protection / `nosniff` / HSTS / `Referrer-Policy`,
cookie `Secure`, `HttpOnly` and `SameSite` flags, version banners, directory
listings, stack traces, database errors, path disclosure, forms posting over
HTTP, password fields on plain HTTP, POST forms with no CSRF token, and mixed
content. Site-wide issues are deduplicated per origin, so one missing header is
one finding, not one per page.

---

## Safety model

### What the scanner refuses to do

- Submit forms containing a **password field**.
- Submit **POST forms** at all unless you explicitly enable it (and never when
  the action looks like login, checkout, delete, upload and similar).
- Touch parameters whose names look like tokens, sessions, keys or passwords.
- Request endpoints whose path suggests a state change (`logout`, `delete`,
  `reset`, …) — they are inventoried without being called.
- Follow a redirect that leaves the approved origin.

### SSRF and scope

- One origin per scan; subdomains only when you opt in.
- Requests to loopback, RFC 1918, CGNAT, link-local (including
  `169.254.169.254`), unique-local (including `fd00:ec2::254`), multicast,
  reserved and documentation ranges are refused — IPv4, IPv6, and IPv4-mapped,
  6to4 and NAT64 forms that wrap a private address.
- **DNS rebinding is handled at connect time.** The HTTP agents use a custom
  `lookup` that validates the address the socket is about to use, so a name that
  passes validation and then re-resolves to `127.0.0.1` still fails.
- Non-web and internal service ports (22, 3306, 5432, 6379, …) are refused.
- Every redirect hop is re-validated against the scope policy.

### Resource limits

Capped server-side and clamped from any client request: pages, crawl depth,
request budget, response size, scan duration, concurrency, redirect count and
URL length. The crawler also caps how many value-variants of the same
path-and-parameter-set it visits, which is what stops calendars and infinite
pagination from consuming the page budget.

### `ALLOW_PRIVATE_TARGETS`

Off by default. Setting it lets you scan `localhost` and private addresses,
which is what you want when testing **your own app in development or on a
staging network** — and it is the one setting that relaxes the SSRF guard.

While it is on, anyone who can reach this API can use the backend to reach
internal hosts. Enable it only on your own workstation, never on a shared
machine or any deployed instance. The dashboard shows a warning banner whenever
the backend reports it as enabled, and the server logs a warning at startup.

---

## Backend API

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/api/health` | liveness |
| `GET` | `/api/config` | default config, hard limits, private-target flag |
| `POST` | `/api/validate-target` | check a URL without starting a scan |
| `POST` | `/api/scans` | start a scan |
| `GET` | `/api/scans` | recent scan summaries |
| `GET` | `/api/scans/:id` | full scan record |
| `GET` | `/api/scans/:id/status` | progress snapshot (polling fallback) |
| `GET` | `/api/scans/:id/findings` | findings; filter by `severity`, `type`, `confidence`, `parameter` |
| `GET` | `/api/scans/:id/endpoints` | endpoints; filter by `method`, `status`, `hasParameters`, `hasForms`, `vulnerable`, `q` |
| `GET` | `/api/scans/:id/events` | **Server-Sent Events** progress stream |
| `POST` | `/api/scans/:id/stop` | stop a running scan |

Starting a scan:

```bash
curl -X POST http://127.0.0.1:4000/api/scans \
  -H 'Content-Type: application/json' \
  -d '{
        "target": "https://example.com",
        "authorized": true,
        "config": { "maxPages": 50, "maxDepth": 2 }
      }'
```

`"authorized": true` is mandatory — the API returns `403 authorization_not_confirmed`
without it.

**SSE events**: `snapshot` (full state on connect), `status`, `progress`,
`endpoint`, `finding`, `log`, `done`. The dashboard falls back to polling
`/status` automatically if the stream cannot be established.

### Data shapes

```jsonc
// finding
{
  "id": "finding-a1b2c3d4e5f6",
  "type": "Reflected XSS",
  "severity": "High",          // Critical | High | Medium | Low | Info
  "confidence": "High",        // High | Medium | Low
  "url": "https://example.com/search?q=xss1a2b3c\"'<>",
  "parameter": "q",
  "method": "GET",
  "description": "…",          // what was observed and what it means
  "evidence": "…",             // the raw comparison the verdict rests on
  "recommendation": "…",
  "references": ["CWE-79"],
  "status": "Open",
  "timestamp": "2026-01-01T12:00:00.000Z"
}

// endpoint
{
  "id": "endpoint-a1b2c3d4e5f6",
  "url": "https://example.com/search?q=test",
  "method": "GET",
  "source": "link",            // seed | link | form | script
  "parameters": ["q"],
  "forms": [],
  "statusCode": 200,
  "vulnerable": false,
  "findingCount": 0
}
```

---

## Scan configuration

Defaults, and the hard ceilings the server clamps to:

| Setting | Default | Max |
|---|---|---|
| Maximum pages | 100 | 250 |
| Maximum depth | 3 | 6 |
| Concurrency | 2 | 4 |
| Delay between requests | 250 ms | 5000 ms |
| Request timeout | 10 s | 30 s |
| Request budget | 1500 | 4000 |
| Scan duration | 10 min | 20 min |
| Response size | 2 MB | 3 MB |

Also configurable: `respectRobots` (on), `allowSubdomains` (off), `testForms`
(on, GET only), `testPostForms` (off), and each detection module.

`robots.txt` is honoured by default including `Crawl-delay`, which raises the
inter-request delay for the whole scan.

---

## Storage

Scan history lives in the browser's `localStorage` under `vulnscan:history:v1` —
no database, and nothing is uploaded anywhere. The server keeps only the most
recent scans in memory so a reload can re-attach to a running scan.

Save, load, delete and clear are all available from the **Scan history** page,
plus per-finding triage (`Open` / `Confirmed` / `False positive` / `Fixed`)
stored with the scan. History is capped (25 scans, trimmed findings and
endpoints) and degrades gracefully when the browser store is full.

No credentials, cookies or API keys are stored: the scanner never collects them,
and cookie values are redacted server-side before they reach a finding.

---

## Testing

```bash
npm test          # or: cd server && npm test
```

34 tests covering:

- **SSRF rules** — loopback, private, CGNAT, link-local, metadata, reserved and
  IPv4-mapped / 6to4 / NAT64 addresses; internal hostnames; the connect-time DNS
  hook.
- **Scope policy** — cross-origin, cross-port and cross-scheme rejection.
- **URL handling** — tracking-parameter dedupe, endpoint signatures, crawl traps.
- **Crawler + detection end to end** against an in-memory vulnerable site
  (`test/fixtures/fakeSite.js`) — no sockets are opened, so the suite never
  touches a third party.
- **API** — authorization requirement, blocked targets, malformed input,
  oversized bodies, unknown scans.

---

## Trying it against the bundled test app

`testbed/vulnerable-app.js` is a deliberately vulnerable localhost-only app with
reflected XSS, error- and boolean-based SQL injection, two flavours of path
traversal, and no security headers. It has no database and no filesystem access
— the "data" is in-memory objects. **Never expose it.**

```bash
# terminal 1
npm run testbed                       # http://127.0.0.1:4500

# terminal 2 - private targets must be enabled for a localhost scan
ALLOW_PRIVATE_TARGETS=true npm run dev:server

# terminal 3
npm run dev:client
```

Scan `http://127.0.0.1:4500`. A typical result is 14 endpoints and 13 findings:
2 reflected XSS, 2 SQL injection (one error-based, one boolean-based), 2 path
traversal, and the passive header/cookie/CSRF findings.

---

## Troubleshooting

**"Hostname … resolves to …, which is not allowed"** — the target is on a
private network. That is the SSRF guard doing its job; see
[`ALLOW_PRIVATE_TARGETS`](#allow_private_targets) if it is your own local app.

**Scan finishes immediately with one endpoint** — the target returned a
non-HTML response, redirected off-origin, or `robots.txt` disallows the start
path. Check the activity log in the progress panel.

**No findings on a site you know is vulnerable** — the parameters may be behind
authentication (this scanner does not log in), in POST forms (opt-in), or the
page may be too dynamic for the behavioural comparisons, which then skip rather
than guess. Passive findings still apply.

**Live progress stops updating** — the dashboard falls back to polling and shows
a note. Check that the backend is running and that a proxy between them is not
buffering `text/event-stream`.

**`429 too_many_scans`** — `MAX_CONCURRENT_SCANS` (default 2) is reached. Stop a
running scan or wait for one to finish.
# Vulntest
