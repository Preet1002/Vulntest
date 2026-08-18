/**
 * Central configuration and hard safety limits.
 *
 * Everything a scan is allowed to do passes through the values in this file.
 * `HARD_LIMITS` can never be exceeded by a client request - the values coming
 * from the API are clamped into range by `resolveScanConfig()`.
 */

const int = (value, fallback) => {
  const parsed = Number.parseInt(value ?? '', 10);
  return Number.isFinite(parsed) ? parsed : fallback;
};

export const SERVER_CONFIG = {
  port: int(process.env.PORT, 4000),
  host: process.env.HOST || '127.0.0.1',
  // Comma separated list of browser origins allowed to talk to this API.
  corsOrigins: (process.env.CORS_ORIGIN || 'http://localhost:5173,http://127.0.0.1:5173')
    .split(',')
    .map((origin) => origin.trim())
    .filter(Boolean),
  // Number of finished scans kept in server memory (the browser keeps history).
  scanRetention: int(process.env.SCAN_RETENTION, 25),
  maxConcurrentScans: int(process.env.MAX_CONCURRENT_SCANS, 2),
  // API-side rate limits. Raised only by the test suite.
  apiRateLimit: int(process.env.API_RATE_LIMIT, 300),
  scanRateLimit: int(process.env.SCAN_RATE_LIMIT, 10),

  /**
   * Operator-only escape hatch for scanning an app on localhost or a private
   * staging network. It is OFF by default and can only be set by whoever starts
   * the process - never by an API request - because turning it on makes the
   * backend able to reach internal hosts, which is exactly the SSRF pivot the
   * guard exists to prevent. Never enable it on a shared or public deployment.
   */
  allowPrivateTargets: process.env.ALLOW_PRIVATE_TARGETS === 'true',
};

/**
 * The scanner always identifies itself. Never make this look like a browser -
 * site owners must be able to recognise and filter our traffic in their logs.
 */
export const SCANNER_USER_AGENT =
  process.env.SCANNER_USER_AGENT ||
  'VulnScanner/1.0 (+authorized-security-testing; safe-checks-only)';

/** Ceilings that a client-supplied scan configuration can never exceed. */
export const HARD_LIMITS = {
  maxPages: 2_000,
  maxDepth: 12,
  concurrency: 8,
  requestTimeoutMs: 30_000,
  delayMs: 5_000,
  maxRequests: 20_000,
  maxScanDurationMs: 60 * 60_000,
  maxResponseBytes: 3 * 1024 * 1024,
  maxRedirects: 8,
  // Distinct query-string variants tested per unique path+parameter-name set.
  // Keeps calendars / paginated archives from producing an endless crawl.
  maxVariantsPerSignature: 50,
  maxUrlLength: 2048,
  maxFindings: 500,
  maxLogEntries: 300,
  // Discovery budgets. These used to be fixed constants inside the crawler,
  // which made every scan converge on the same small request count no matter
  // how big the target was.
  maxSitemapUrls: 5_000,
  maxSitemapDocuments: 25,
  maxScriptFiles: 60,
  maxApiProbes: 200,
};

/** Defaults used when the dashboard does not override them. */
export const DEFAULT_SCAN_CONFIG = {
  maxPages: 500,
  maxDepth: 6,
  concurrency: 4,
  requestTimeoutMs: 10_000,
  delayMs: 250,
  maxRequests: 6_000,
  maxScanDurationMs: 20 * 60_000,
  maxResponseBytes: 2 * 1024 * 1024,
  maxRedirects: 5,
  maxVariantsPerSignature: 20,
  respectRobots: true,
  allowSubdomains: false,
  // Read /sitemap.xml (and any Sitemap: line in robots.txt) to seed the crawl.
  // Link-following alone misses whole sections of most real sites.
  useSitemap: true,
  // If the start URL redirects to another host (the usual apex -> www hop),
  // re-pin the scan to wherever it landed instead of crawling nothing.
  followHostRedirect: true,
  checks: {
    xss: true,
    sqli: true,
    pathTraversal: true,
    passive: true,
  },
  // GET forms are safe to exercise. POST forms can create state on the target,
  // so they stay opt-in and are additionally filtered for sensitive actions.
  testForms: true,
  testPostForms: false,
};

const clamp = (value, min, max, fallback) => {
  const parsed = Number(value);
  if (!Number.isFinite(parsed)) return fallback;
  return Math.min(max, Math.max(min, Math.round(parsed)));
};

/**
 * Merge a client-supplied config with the defaults and clamp every value to a
 * safe range. Unknown keys are dropped.
 */
export function resolveScanConfig(input = {}) {
  const source = input && typeof input === 'object' ? input : {};
  const checks = source.checks && typeof source.checks === 'object' ? source.checks : {};

  return {
    maxPages: clamp(source.maxPages, 1, HARD_LIMITS.maxPages, DEFAULT_SCAN_CONFIG.maxPages),
    maxDepth: clamp(source.maxDepth, 0, HARD_LIMITS.maxDepth, DEFAULT_SCAN_CONFIG.maxDepth),
    concurrency: clamp(source.concurrency, 1, HARD_LIMITS.concurrency, DEFAULT_SCAN_CONFIG.concurrency),
    requestTimeoutMs: clamp(
      source.requestTimeoutMs,
      1_000,
      HARD_LIMITS.requestTimeoutMs,
      DEFAULT_SCAN_CONFIG.requestTimeoutMs,
    ),
    delayMs: clamp(source.delayMs, 0, HARD_LIMITS.delayMs, DEFAULT_SCAN_CONFIG.delayMs),
    maxRequests: clamp(source.maxRequests, 1, HARD_LIMITS.maxRequests, DEFAULT_SCAN_CONFIG.maxRequests),
    maxScanDurationMs: clamp(
      source.maxScanDurationMs,
      10_000,
      HARD_LIMITS.maxScanDurationMs,
      DEFAULT_SCAN_CONFIG.maxScanDurationMs,
    ),
    maxResponseBytes: clamp(
      source.maxResponseBytes,
      64 * 1024,
      HARD_LIMITS.maxResponseBytes,
      DEFAULT_SCAN_CONFIG.maxResponseBytes,
    ),
    maxRedirects: clamp(source.maxRedirects, 0, HARD_LIMITS.maxRedirects, DEFAULT_SCAN_CONFIG.maxRedirects),
    maxVariantsPerSignature: clamp(
      source.maxVariantsPerSignature,
      1,
      HARD_LIMITS.maxVariantsPerSignature,
      DEFAULT_SCAN_CONFIG.maxVariantsPerSignature,
    ),
    respectRobots: source.respectRobots !== false,
    allowSubdomains: source.allowSubdomains === true,
    useSitemap: source.useSitemap !== false,
    followHostRedirect: source.followHostRedirect !== false,
    checks: {
      xss: checks.xss !== false,
      sqli: checks.sqli !== false,
      pathTraversal: checks.pathTraversal !== false,
      passive: checks.passive !== false,
    },
    testForms: source.testForms !== false,
    testPostForms: source.testPostForms === true,
  };
}

export const SEVERITY = {
  CRITICAL: 'Critical',
  HIGH: 'High',
  MEDIUM: 'Medium',
  LOW: 'Low',
  INFO: 'Info',
};

export const CONFIDENCE = {
  HIGH: 'High',
  MEDIUM: 'Medium',
  LOW: 'Low',
};

export const SEVERITY_ORDER = [
  SEVERITY.CRITICAL,
  SEVERITY.HIGH,
  SEVERITY.MEDIUM,
  SEVERITY.LOW,
  SEVERITY.INFO,
];
