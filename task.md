# Build an Authorized Web Vulnerability Scanner

Build a full-stack web vulnerability scanning application for **authorized security testing of websites**. The user should enter a website URL, start a scan, and see the discovered endpoints and potential vulnerabilities in a single dashboard.

The application is intended for testing websites that the user owns or has explicit permission to assess. Do not implement destructive exploitation, credential attacks, authentication bypasses, denial-of-service behavior, or aggressive scanning.

## 1. Technology Stack

### Frontend

* React
* Vite
* Tailwind CSS
* Axios
* React Router if multiple pages are useful
* Recharts or another lightweight charting library for dashboard statistics

### Backend

* Node.js
* Express.js
* Axios/fetch for HTTP requests
* Cheerio for HTML parsing
* A crawler/queue architecture for discovering links and endpoints
* Local JSON/SQLite storage if persistent backend scan history is required

### Storage

For the initial version:

* Store scan history and dashboard state in browser `localStorage`.
* Do not require a database.
* The backend should expose APIs for starting scans and retrieving scan results.
* The frontend should persist completed scan summaries/results in `localStorage`.

## 2. Main User Flow

The application should work like this:

1. User opens the dashboard.
2. User enters a target URL, for example:
   `https://example.com`
3. User clicks **Start Scan**.
4. Frontend sends the URL to the Node.js backend.
5. Backend validates the URL and begins crawling the authorized target.
6. Crawler discovers:

   * Internal pages
   * Links
   * Forms
   * Query parameters
   * URL paths
   * API-like endpoints visible in HTML/JavaScript
7. Scanner performs safe vulnerability checks against discovered endpoints.
8. Backend streams or periodically returns scan progress.
9. Dashboard displays:

   * Scan progress
   * Discovered endpoints
   * Vulnerability count
   * Severity
   * Vulnerability type
   * Affected URL/parameter
   * Evidence
   * Remediation advice
10. When the scan finishes, save the complete result to `localStorage`.

## 3. Crawling Engine

Implement a controlled crawler.

Requirements:

* Start from the supplied URL.
* Stay within the same origin by default.
* Normalize URLs to prevent duplicates.
* Maintain a queue of URLs to visit.
* Maintain a `visited` set.
* Extract `<a href>`, `<form>`, script references and other relevant URL information.
* Extract query parameters from URLs.
* Detect forms and record:

  * method
  * action
  * input names
  * input types
* Respect `robots.txt` where appropriate.
* Set a configurable maximum crawl depth.
* Set a configurable maximum number of pages.
* Set a configurable request rate/concurrency.
* Set reasonable request timeouts.
* Avoid infinite crawling caused by calendars, tracking parameters, session parameters, etc.

Example scan configuration:

```text
Maximum pages: 100
Maximum depth: 3
Concurrency: 2
Request timeout: 10 seconds
Delay between requests: configurable
```

Do not perform aggressive crawling.

## 4. Proxy / Request Layer

Create a backend request/proxy layer so that the browser does not directly make every request to the target.

Architecture:

```text
React Dashboard
       |
       v
Node.js API
       |
       v
Crawler / Scanner
       |
       v
HTTP Request Layer
       |
       v
Authorized Target Website
```

The proxy/request layer should:

* Centralize HTTP requests.
* Apply request timeouts.
* Apply rate limiting.
* Identify the scanner with a clear User-Agent.
* Handle redirects safely.
* Prevent requests to localhost, private IP ranges, cloud metadata endpoints, or other unintended internal targets.
* Prevent the scanner from becoming an open SSRF proxy.
* Restrict requests to the approved target origin.
* Limit concurrent requests.

Do **not** use the proxy to bypass WAFs, CAPTCHAs, authentication controls, IP bans, or security protections.

## 5. XSS Detection

Implement safe detection for common reflected XSS indicators.

For discovered query parameters and suitable form inputs:

1. Identify parameters that are reflected into the HTTP response.
2. Use a unique harmless canary value such as:

```text
xss_scan_<random_id>
```

3. Check whether the value appears in the response.
4. Determine the context in which it appears:

   * HTML text
   * HTML attribute
   * JavaScript
   * URL
   * Other contexts
5. Report a potential XSS finding only when there is meaningful evidence that user-controlled input is reflected unsafely.

Do not use payloads intended to execute malicious JavaScript against third-party users.

The result should contain:

```text
Type: Reflected XSS
Severity: Medium/High depending on evidence
URL: ...
Parameter: ...
Evidence: ...
Confidence: ...
Recommendation: Context-aware output encoding / sanitization
```

Clearly distinguish:

* Confirmed/strong evidence
* Likely vulnerability
* Potential reflection

Do not label simple reflection automatically as confirmed XSS.

## 6. SQL Injection Detection

Implement conservative SQL injection detection.

For suitable query parameters:

* Establish a baseline response.
* Compare behavior when the parameter is modified with safe test inputs.
* Look for meaningful differences such as:

  * Database error signatures
  * Consistent response anomalies
  * Unexpected server errors
  * Strong behavioral differences suggesting unsafe query construction

Do not perform destructive SQL commands.

Do not:

* Modify/delete database records.
* Dump database contents.
* Attempt authentication bypass.
* Enumerate credentials.
* Extract sensitive data.

The scanner should report suspicious behavior as:

```text
Type: Potential SQL Injection
Severity: High
URL: ...
Parameter: ...
Evidence: ...
Confidence: ...
Recommendation: Use parameterized queries/prepared statements
```

Avoid claiming SQL injection solely because a generic `500` response occurred.

## 7. Path Traversal Detection

Identify endpoints that appear to accept file/path parameters.

Examples:

```text
/file?path=
/download?file=
/view?filename=
```

Perform conservative path traversal detection using non-destructive test cases and response comparison.

Look for evidence that a parameter can cause access outside its intended directory.

Do not attempt to retrieve sensitive operating-system files.

The scanner should report:

```text
Type: Potential Path Traversal
Severity: High
URL: ...
Parameter: ...
Evidence: ...
Confidence: ...
Recommendation: Canonicalize paths and enforce an allowlisted base directory
```

## 8. Endpoint Discovery

Create an endpoint inventory.

Each endpoint should contain:

```json
{
  "url": "https://example.com/search?q=test",
  "method": "GET",
  "source": "link",
  "parameters": ["q"],
  "forms": [],
  "statusCode": 200
}
```

The dashboard should allow filtering endpoints by:

* HTTP method
* Status code
* Parameters
* Forms
* Vulnerability status

## 9. Vulnerability Data Model

Each finding should have:

```json
{
  "id": "finding-123",
  "type": "XSS",
  "severity": "High",
  "confidence": "High",
  "url": "https://example.com/search?q=test",
  "parameter": "q",
  "method": "GET",
  "description": "...",
  "evidence": "...",
  "recommendation": "...",
  "timestamp": "..."
}
```

Severity levels:

```text
Critical
High
Medium
Low
Info
```

## 10. Dashboard UI

Create a professional security-dashboard interface.

### Header

Show:

```text
Web Vulnerability Scanner
Authorized Security Testing
```

Include:

* Target URL input
* Start Scan button
* Stop Scan button
* Scan configuration button

### Summary Cards

Display:

```text
Pages Crawled
Endpoints Found
Vulnerabilities
High
Medium
Low
```

### Scan Progress

Show:

* Progress bar
* Current URL
* Pages scanned
* Endpoints discovered
* Requests performed
* Current scanner status

### Vulnerability Table

Columns:

```text
Severity
Type
URL
Parameter
Confidence
Status
```

Clicking a finding should open a detailed panel containing:

* Vulnerability type
* Severity
* Confidence
* Affected endpoint
* Parameter
* Evidence
* Explanation
* Remediation
* Detection timestamp

### Endpoint Explorer

Display all discovered endpoints in a searchable table.

### Scan History

Display previous scans stored in `localStorage`.

Each scan should show:

```text
Target
Date
Pages
Endpoints
Vulnerabilities
High
Medium
Low
```

Allow the user to open or delete previous scan results.

## 11. Dashboard Charts

Add useful visualizations:

* Vulnerabilities by severity
* Vulnerabilities by type
* Scan progress
* Endpoint status-code distribution

Example:

```text
XSS              3
SQL Injection    1
Path Traversal   2
```

## 12. LocalStorage

Store scan results using a structure similar to:

```javascript
{
  id: "...",
  target: "...",
  startedAt: "...",
  completedAt: "...",
  statistics: {
    pages: 25,
    endpoints: 41,
    vulnerabilities: 6
  },
  findings: [],
  endpoints: []
}
```

Implement:

* Save scan
* Load scan
* Delete scan
* Clear history

Do not store passwords, authentication cookies, API keys, or other sensitive secrets in `localStorage`.

## 13. Backend API

Implement APIs similar to:

```text
POST /api/scans
GET  /api/scans/:id
GET  /api/scans/:id/status
GET  /api/scans/:id/findings
GET  /api/scans/:id/endpoints
POST /api/scans/:id/stop
```

For scan progress, use either:

* Server-Sent Events (preferred), or
* WebSockets.

This should allow the React dashboard to update without repeatedly refreshing the page.

## 14. Security Requirements

The scanner itself must be secure.

Implement:

* URL validation
* Same-origin restrictions
* SSRF protection
* Private IP blocking
* localhost blocking
* DNS rebinding protection
* Request timeout
* Rate limiting
* Maximum crawl depth
* Maximum page count
* Maximum response size
* Maximum scan duration
* Concurrency limits
* Redirect validation
* Input sanitization
* Error handling

The backend must never become a general-purpose URL-fetching proxy.

Only scan targets explicitly supplied by the user and require the target to be publicly reachable or otherwise intentionally accessible to the scanner.

## 15. Project Structure

Use a clean structure:

```text
vulnerability-scanner/
│
├── client/
│   ├── src/
│   │   ├── components/
│   │   ├── pages/
│   │   ├── services/
│   │   ├── hooks/
│   │   ├── utils/
│   │   └── App.jsx
│   └── package.json
│
├── server/
│   ├── src/
│   │   ├── crawler/
│   │   ├── scanner/
│   │   │   ├── xss.js
│   │   │   ├── sqli.js
│   │   │   └── pathTraversal.js
│   │   ├── routes/
│   │   ├── middleware/
│   │   ├── services/
│   │   └── server.js
│   └── package.json
│
└── README.md
```

## 16. Development Requirements

Build the application incrementally.

Start with:

1. React dashboard
2. Node/Express backend
3. URL validation
4. Crawler
5. Endpoint discovery
6. Scan job management
7. XSS detection
8. SQL injection detection
9. Path traversal detection
10. Real-time progress
11. Dashboard visualization
12. LocalStorage persistence
13. Scan history
14. Error handling and security hardening

For every stage:

* Provide the required files.
* Explain where each file belongs.
* Give installation commands.
* Give commands to run frontend and backend.
* Keep the code modular.
* Do not put the entire application into one file.

## 17. Important Constraint

This is an **authorized vulnerability assessment tool**, not an exploitation framework.

The scanner should identify and provide evidence for potential vulnerabilities while minimizing impact on the target.

Do not implement:

* destructive payloads
* data extraction
* credential theft
* authentication bypass
* WAF/CAPTCHA bypass
* stealth/evasion mechanisms
* denial-of-service testing
* malware
* persistence

Focus on endpoint discovery, safe detection, evidence collection, visualization, remediation guidance, and a professional security-testing dashboard.

## Final Goal

The finished application should allow the user to enter:

```text
https://authorized-target.example
```

and receive a dashboard like:

```text
┌──────────────────────────────────────────────┐
│       WEB VULNERABILITY SCANNER              │
├──────────────────────────────────────────────┤
│ Target: https://authorized-target.example    │
│                                              │
│ Pages       Endpoints      Vulnerabilities   │
│  32            57                6           │
│                                              │
│ High: 2    Medium: 3    Low: 1              │
├──────────────────────────────────────────────┤
│ Vulnerabilities                              │
│                                              │
│ HIGH   Potential SQL Injection               │
│        /search?q=                            │
│                                              │
│ HIGH   Potential Path Traversal              │
│        /download?file=                       │
│                                              │
│ MED    Reflected XSS                         │
│        /search?q=                            │
├──────────────────────────────────────────────┤
│ Discovered Endpoints                         │
│                                              │
│ GET  /                                       │
│ GET  /search?q=                              │
│ GET  /products?id=                           │
│ POST /login                                  │
└──────────────────────────────────────────────┘
```

Prioritize **correctness, safety, clean architecture, real-time scan progress, and a polished React dashboard** over implementing aggressive exploitation techniques.