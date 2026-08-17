/**
 * An in-memory deliberately-vulnerable site plus a fake HTTP client.
 *
 * This lets the crawler and every detection module be exercised end to end
 * without opening a socket - which matters here, because the SSRF guard blocks
 * localhost by design and we must never point the test suite at a third party.
 */

export const ORIGIN = 'https://test.example';

const page = (body, title = 'Test site') => `<!doctype html>
<html><head><title>${title}</title></head><body>${body}</body></html>`;

const html = (body, extra = {}) => ({
  status: 200,
  headers: { 'content-type': 'text/html; charset=utf-8', ...extra },
  body: page(body),
});

const notFound = (message = 'Not found') => ({
  status: 404,
  headers: { 'content-type': 'text/html' },
  body: page(`<h1>404</h1><p>${message}</p>`),
});

/** Odd number of single quotes => the value would break out of a SQL string. */
const unbalancedQuote = (value) => (String(value).split("'").length - 1) % 2 === 1;

/**
 * Resolve a relative path the way a naive server would: join it onto a base
 * directory and collapse "..". Used by the traversal fixtures.
 */
function resolveNaively(value) {
  const segments = `content/${value}`.split('/');
  const stack = [];
  for (const segment of segments) {
    if (segment === '' || segment === '.') continue;
    if (segment === '..') stack.pop();
    else stack.push(segment);
  }
  return stack.join('/');
}

const FILES = new Set(['content/report.txt', 'content/doc.txt', 'report.txt', 'doc.txt']);

/**
 * @param {string} rawUrl
 * @param {string} method
 * @param {string|null} body form-encoded request body
 */
export function handleRequest(rawUrl, method = 'GET', body = null) {
  const url = new URL(rawUrl);
  const path = url.pathname;
  const params = url.searchParams;
  if (method === 'POST' && body) {
    for (const [name, value] of new URLSearchParams(body)) params.set(name, value);
  }

  // Every page is served without security headers and with a bare session
  // cookie, so the passive checks have something to find.
  const sessionCookie = { 'set-cookie': ['sessionid=abc123; Path=/'] };

  if (path === '/robots.txt') {
    return { status: 200, headers: { 'content-type': 'text/plain' }, body: 'User-agent: *\nDisallow: /admin\n' };
  }

  if (path === '/') {
    return html(
      `<h1>Test shop</h1>
       <nav>
         <a href="/search?q=test">Search</a>
         <a href="/product?id=1">Product</a>
         <a href="/list?cat=shoes">Catalogue</a>
         <a href="/download?file=report.txt">Download</a>
         <a href="/view?path=doc.txt">View doc</a>
         <a href="/about">About</a>
         <a href="/admin">Admin</a>
         <a href="https://other.example/offsite">Offsite</a>
       </nav>
       <form action="/search" method="GET"><input type="text" name="q"><input type="submit"></form>
       <form action="/subscribe" method="POST"><input type="email" name="email"><input type="submit"></form>
       <script>fetch("/api/v1/products?limit=10");</script>
       <script src="/static/app.js"></script>`,
      sessionCookie,
    );
  }

  if (path === '/about') return html('<p>About us</p>', sessionCookie);

  if (path === '/admin') return html('<p>Admin area</p>');

  if (path === '/static/app.js') {
    return {
      status: 200,
      headers: { 'content-type': 'application/javascript' },
      body: 'const base = "/api/v1/users"; axios.get("/api/v1/orders?page=1");',
    };
  }

  if (path.startsWith('/api/')) {
    return { status: 200, headers: { 'content-type': 'application/json' }, body: '{"items":[]}' };
  }

  // --- reflected XSS: value written into HTML text with no encoding ---------
  if (path === '/search') {
    const q = params.get('q') ?? '';
    return html(`<h2>Results</h2><p>You searched for ${q}</p><ul></ul>`, sessionCookie);
  }

  // --- error-based SQL injection -------------------------------------------
  if (path === '/product') {
    const id = params.get('id') ?? '';
    if (unbalancedQuote(id)) {
      return {
        status: 500,
        headers: { 'content-type': 'text/html' },
        body: page(
          '<h1>Database error</h1><pre>You have an error in your SQL syntax; check the manual that corresponds ' +
            `to your MySQL server version for the right syntax to use near '${id}' at line 1</pre>`,
        ),
      };
    }
    return html(`<h2>Product ${Number.parseInt(id, 10) || 1}</h2><p>A fine product.</p>`, sessionCookie);
  }

  // --- boolean-based SQL injection (no error output) ------------------------
  if (path === '/list') {
    const cat = params.get('cat') ?? '';
    // A naive WHERE clause: an always-false condition returns no rows.
    // The injected condition closes with the application's own quote, so the
    // probe value ends at ...'1'='2 with no trailing quote.
    if (/\b1\s*=\s*2\b|'1'\s*=\s*'2/.test(cat)) {
      return html('<h2>Catalogue</h2><p>No items matched.</p>', sessionCookie);
    }
    return html(
      '<h2>Catalogue</h2><ul><li>Runner</li><li>Sandal</li><li>Boot</li><li>Loafer</li></ul>',
      sessionCookie,
    );
  }

  // --- path traversal, error based -----------------------------------------
  if (path === '/download') {
    const file = params.get('file') ?? '';
    const resolved = resolveNaively(file);
    if (FILES.has(resolved)) {
      return { status: 200, headers: { 'content-type': 'text/plain' }, body: 'report contents\n' };
    }
    return {
      status: 500,
      headers: { 'content-type': 'text/html' },
      body: page(
        `<h1>Error</h1><pre>Error: ENOENT: no such file or directory, open '/var/www/app/${resolved}'</pre>`,
      ),
    };
  }

  // --- path traversal, behaviour based (no error message) -------------------
  if (path === '/view') {
    const target = params.get('path') ?? '';
    const resolved = resolveNaively(target);
    if (FILES.has(resolved)) {
      return html('<h2>Document</h2><p>The quick brown fox jumps over the lazy dog.</p>', sessionCookie);
    }
    return notFound('Document unavailable');
  }

  if (path === '/subscribe') {
    return html('<p>Thanks for subscribing.</p>');
  }

  return notFound();
}

/**
 * Drop-in replacement for ScannerHttpClient that serves the fixture above.
 * Mirrors the real client's result shape exactly.
 */
export class FakeHttpClient {
  constructor({ ctx = null, handler = handleRequest, maxRequests = 2000 } = {}) {
    this.ctx = ctx;
    this.handler = handler;
    this.maxRequests = maxRequests;
    this.requestCount = 0;
    this.errorCount = 0;
    this.bytesReceived = 0;
    this.requests = [];
    this.limiter = { setMinimumDelay() {} };
  }

  get budgetExhausted() {
    return this.requestCount >= this.maxRequests;
  }

  async request({ url, method = 'GET', data = null, purpose = 'crawl' } = {}) {
    const requestedUrl = url instanceof URL ? url.href : String(url);
    this.requestCount += 1;
    this.requests.push({ url: requestedUrl, method, purpose });

    let response;
    try {
      response = this.handler(requestedUrl, method.toUpperCase(), data);
    } catch (error) {
      response = { status: 500, headers: {}, body: `handler error: ${error.message}` };
    }

    const result = {
      ok: true,
      url: requestedUrl,
      requestedUrl,
      method: method.toUpperCase(),
      status: response.status,
      headers: response.headers || {},
      body: response.body || '',
      contentType: (response.headers || {})['content-type'] || '',
      bytes: Buffer.byteLength(response.body || ''),
      timeMs: 1,
      redirects: [],
      error: null,
      truncated: false,
    };

    this.bytesReceived += result.bytes;
    this.ctx?.recordRequest({
      url: result.url,
      method: result.method,
      status: result.status,
      purpose,
      timeMs: 1,
      error: null,
    });
    return result;
  }

  get(url, options = {}) {
    return this.request({ ...options, url, method: 'GET' });
  }

  postForm(url, fields, options = {}) {
    return this.request({
      ...options,
      url,
      method: 'POST',
      data: new URLSearchParams(fields).toString(),
    });
  }
}
