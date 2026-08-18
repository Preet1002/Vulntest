/**
 * End-to-end crawl + detection run against the in-memory fixture site.
 * No sockets are opened and no third-party host is contacted.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { ScanContext } from '../src/services/scanContext.js';
import { TargetPolicy } from '../src/security/targetPolicy.js';
import { crawl } from '../src/crawler/crawler.js';
import { runActiveScan } from '../src/scanner/index.js';
import { resolveScanConfig } from '../src/config/index.js';
import { emptyStatistics, SCAN_STATUS } from '../src/services/scanStore.js';
import { parseHtml } from '../src/crawler/parser.js';
import { determineContext } from '../src/scanner/xss.js';
import { FakeHttpClient, ORIGIN } from './fixtures/fakeSite.js';
import { parseSitemap, collectSitemapUrls } from '../src/services/sitemap.js';
import { parseRobots, RobotsPolicy } from '../src/services/robots.js';

function makeContext(overrides = {}) {
  const config = resolveScanConfig({ maxPages: 30, maxDepth: 3, concurrency: 2, delayMs: 0, testPostForms: false, ...overrides });
  const scan = {
    id: 'scan_test',
    target: `${ORIGIN}/`,
    origin: ORIGIN,
    status: SCAN_STATUS.CRAWLING,
    phase: 'crawling',
    progress: 0,
    currentUrl: null,
    config,
    startedAt: new Date().toISOString(),
    completedAt: null,
    statistics: { ...emptyStatistics(), parametersTested: 0 },
    findings: [],
    endpoints: [],
    log: [],
    error: null,
  };
  const ctx = new ScanContext(scan, new TargetPolicy(new URL(`${ORIGIN}/`)));
  ctx.http = new FakeHttpClient({ ctx });
  return ctx;
}

const typesOf = (ctx) => ctx.scan.findings.map((finding) => finding.type);
const findingFor = (ctx, type, parameter) =>
  ctx.scan.findings.find((f) => f.type === type && (!parameter || f.parameter === parameter));

test('crawler discovers pages, forms, parameters and script endpoints', async () => {
  const ctx = makeContext();
  await crawl(ctx);

  const urls = ctx.endpoints.map((endpoint) => endpoint.url);
  assert.ok(urls.some((url) => url.endsWith('/search?q=test')), 'query endpoint discovered');
  assert.ok(urls.some((url) => url.includes('/product?id=1')), 'product endpoint discovered');
  assert.ok(urls.some((url) => url.includes('/api/v1/products')), 'endpoint from inline script discovered');
  assert.ok(urls.some((url) => url.includes('/api/v1/orders')), 'endpoint from external script discovered');

  // Scope is enforced: nothing off-origin is ever requested.
  assert.ok(!urls.some((url) => url.includes('other.example')), 'off-origin link not crawled');
  for (const request of ctx.http.requests) {
    assert.ok(request.url.startsWith(ORIGIN), `request stayed in scope: ${request.url}`);
  }

  const searchForm = ctx.endpoints.find((endpoint) => endpoint.forms.length > 0);
  assert.ok(searchForm, 'form endpoint recorded');
  assert.equal(searchForm.forms[0].inputs[0].name, 'q');

  const seed = ctx.endpoints.find((endpoint) => endpoint.url === `${ORIGIN}/`);
  assert.equal(seed.statusCode, 200);
  assert.equal(seed.title, 'Test site');
});

test('robots.txt disallow keeps the crawler out of /admin', async () => {
  const ctx = makeContext();
  const { loadRobots } = await import('../src/services/robots.js');
  ctx.robots = await loadRobots(ctx.http, ORIGIN);
  await crawl(ctx);

  assert.ok(!ctx.endpoints.some((endpoint) => endpoint.url.includes('/admin')), '/admin was not crawled');
});

test('reflected XSS is reported with context and unencoded characters', async () => {
  const ctx = makeContext();
  await crawl(ctx);
  await runActiveScan(ctx);

  const xss = findingFor(ctx, 'Reflected XSS', 'q');
  assert.ok(xss, `expected a Reflected XSS finding, got: ${typesOf(ctx).join(', ')}`);
  assert.equal(xss.severity, 'High');
  assert.equal(xss.confidence, 'High');
  assert.match(xss.evidence, /HTML text/);
  assert.match(xss.evidence, /Unencoded characters: " ' < >/);
});

test('error-based SQL injection is reported for the quote-sensitive parameter', async () => {
  const ctx = makeContext();
  await crawl(ctx);
  await runActiveScan(ctx);

  const sqli = findingFor(ctx, 'Potential SQL Injection', 'id');
  assert.ok(sqli, `expected a SQL injection finding, got: ${typesOf(ctx).join(', ')}`);
  assert.equal(sqli.severity, 'High');
  assert.equal(sqli.confidence, 'High');
  assert.match(sqli.evidence, /MySQL/);
});

test('boolean-based SQL injection is reported without any error message', async () => {
  const ctx = makeContext();
  await crawl(ctx);
  await runActiveScan(ctx);

  const sqli = findingFor(ctx, 'Potential SQL Injection', 'cat');
  assert.ok(sqli, 'expected a boolean-based SQL injection finding');
  assert.equal(sqli.confidence, 'Medium');
  assert.match(sqli.evidence, /TRUE .* similarity/);
});

test('path traversal is reported from both the error and the behavioural probe', async () => {
  const ctx = makeContext();
  await crawl(ctx);
  await runActiveScan(ctx);

  const errorBased = findingFor(ctx, 'Potential Path Traversal', 'file');
  assert.ok(errorBased, 'expected an error-based traversal finding');
  assert.match(errorBased.evidence, /ENOENT/);
  assert.match(errorBased.description, /var\/www\/app/);

  const behavioural = findingFor(ctx, 'Potential Path Traversal', 'path');
  assert.ok(behavioural, 'expected a behavioural traversal finding');
  assert.match(behavioural.evidence, /Self-cancelling traversal/);
});

test('passive checks report missing headers and cookie flags once per origin', async () => {
  const ctx = makeContext();
  await crawl(ctx);

  const types = typesOf(ctx);
  for (const expected of [
    'Missing Content-Security-Policy',
    'Missing Clickjacking Protection',
    'Missing X-Content-Type-Options',
    'Missing HTTP Strict Transport Security',
    'Session Cookie Without HttpOnly',
    'Cookie Without Secure Flag',
    'Form Without CSRF Token',
  ]) {
    assert.ok(types.includes(expected), `expected passive finding: ${expected}`);
  }

  const cspCount = types.filter((type) => type === 'Missing Content-Security-Policy').length;
  assert.equal(cspCount, 1, 'site-wide header findings are deduplicated');
});

test('sensitive parameters and POST forms are excluded from active testing', async () => {
  const ctx = makeContext();
  await crawl(ctx);
  await runActiveScan(ctx);

  const probed = ctx.http.requests.filter((request) => request.method === 'POST');
  assert.equal(probed.length, 0, 'POST forms are not submitted unless explicitly enabled');
});

test('findings are linked back to the endpoints they came from', async () => {
  const ctx = makeContext();
  await crawl(ctx);
  await runActiveScan(ctx);

  const flagged = ctx.endpoints.filter((endpoint) => endpoint.vulnerable);
  assert.ok(flagged.length > 1, 'several endpoints should carry findings');
  // The probe URL carries a random canary, so matching must ignore the query.
  const search = ctx.endpoints.find((endpoint) => endpoint.url.includes('/search'));
  assert.equal(search.vulnerable, true);
  assert.ok(search.findingCount >= 1);
});

test('a repeated finding for the same parameter is only reported once', async () => {
  const ctx = makeContext();
  await crawl(ctx);

  const base = {
    type: 'Reflected XSS',
    severity: 'High',
    confidence: 'High',
    parameter: 'q',
    method: 'GET',
    description: 'x',
    evidence: 'x',
    recommendation: 'x',
  };
  // Same parameter, different probe values in the URL.
  assert.ok(ctx.addFinding({ ...base, url: `${ORIGIN}/search?q=probe-one` }));
  assert.equal(ctx.addFinding({ ...base, url: `${ORIGIN}/search?q=probe-two` }), null);
  assert.ok(ctx.addFinding({ ...base, url: `${ORIGIN}/other?q=probe-three` }), 'a different path is a different finding');
});

test('stopping a scan halts further requests', async () => {
  const ctx = makeContext();
  ctx.stop('stopped by user');
  await crawl(ctx);
  assert.equal(ctx.http.requestCount, 0);
});

test('scan limits are enforced', async () => {
  const ctx = makeContext({ maxPages: 3 });
  await crawl(ctx);
  assert.ok(ctx.scan.statistics.pages <= 3, `expected at most 3 pages, got ${ctx.scan.statistics.pages}`);
});

test('XSS context detection classifies each reflection context', () => {
  const cases = [
    ['<p>hello TOKEN</p>', 'HTML text'],
    ['<input value="TOKEN">', 'HTML attribute'],
    ['<a href="/x?q=TOKEN">l</a>', 'URL attribute'],
    ['<div onclick="f(\'TOKEN\')">', 'Event handler attribute'],
    ['<script>var a = "TOKEN";</script>', 'JavaScript'],
    ['<!-- TOKEN -->', 'HTML comment'],
  ];
  for (const [body, expected] of cases) {
    const index = body.indexOf('TOKEN');
    assert.equal(determineContext(body, index).context, expected, body);
  }
});

test('form parsing records method, action, input names and types', () => {
  const parsed = parseHtml(
    `<form method="post" action="/submit"><input name="a" type="text"><textarea name="b"></textarea>
     <select name="c"><option>1</option></select><input name="d" type="password"></form>`,
    'https://x.example/page',
  );
  const [form] = parsed.forms;
  assert.equal(form.method, 'POST');
  assert.equal(form.action, 'https://x.example/submit');
  assert.deepEqual(
    form.inputs.map((input) => `${input.name}:${input.type}`),
    ['a:text', 'b:textarea', 'c:select', 'd:password'],
  );
});

// --- discovery: sitemaps ----------------------------------------------------

test('sitemap parser reads XML, plain text and entity-escaped URLs', () => {
  const xml = `<?xml version="1.0"?><urlset>
    <url><loc>${ORIGIN}/a?x=1&amp;y=2</loc></url>
    <url><loc>${ORIGIN}/b</loc></url></urlset>`;
  assert.deepEqual(parseSitemap(xml), [`${ORIGIN}/a?x=1&y=2`, `${ORIGIN}/b`]);

  assert.deepEqual(parseSitemap(`${ORIGIN}/one\n${ORIGIN}/two\n`), [`${ORIGIN}/one`, `${ORIGIN}/two`]);
  assert.deepEqual(parseSitemap('<urlset></urlset>'), []);
});

test('robots.txt Sitemap directives are kept alongside the rules', () => {
  const policy = new RobotsPolicy(
    parseRobots(`User-agent: *\nDisallow: /admin\n\nSitemap: ${ORIGIN}/sitemap.xml\n`),
  );
  assert.deepEqual(policy.sitemaps, [`${ORIGIN}/sitemap.xml`]);
  assert.equal(policy.isAllowed(`${ORIGIN}/admin`), false);
});

test('sitemap discovery follows an index and stays inside the target scope', async () => {
  const ctx = makeContext();
  const documents = {
    [`${ORIGIN}/sitemap.xml`]: `<?xml version="1.0"?><sitemapindex>
      <sitemap><loc>${ORIGIN}/sitemap-1.xml</loc></sitemap></sitemapindex>`,
    [`${ORIGIN}/sitemap-1.xml`]: `<?xml version="1.0"?><urlset>
      <url><loc>${ORIGIN}/deep/1</loc></url>
      <url><loc>${ORIGIN}/deep/2</loc></url>
      <url><loc>https://other.example/off-site</loc></url></urlset>`,
  };
  ctx.http = new FakeHttpClient({
    ctx,
    handler: (url) =>
      documents[url]
        ? { status: 200, headers: { 'content-type': 'application/xml' }, body: documents[url] }
        : { status: 404, headers: { 'content-type': 'text/html' }, body: 'no' },
  });

  const { urls } = await collectSitemapUrls(ctx, [`${ORIGIN}/sitemap.xml`]);
  assert.deepEqual(urls.sort(), [`${ORIGIN}/deep/1`, `${ORIGIN}/deep/2`]);
});

test('the crawler reaches pages that are only listed in a sitemap', async () => {
  const ctx = makeContext({ maxPages: 50 });
  const sitemap = `<?xml version="1.0"?><urlset>${Array.from(
    { length: 20 },
    (_, index) => `<url><loc>${ORIGIN}/archive/${index}</loc></url>`,
  ).join('')}</urlset>`;

  ctx.http = new FakeHttpClient({
    ctx,
    handler: (url) => {
      if (url === `${ORIGIN}/sitemap.xml`) {
        return { status: 200, headers: { 'content-type': 'application/xml' }, body: sitemap };
      }
      if (url.includes('/sitemap')) return { status: 404, headers: {}, body: '' };
      // The front page links to nothing at all - the archive is sitemap-only.
      return {
        status: 200,
        headers: { 'content-type': 'text/html' },
        body: '<!doctype html><html><head><title>t</title></head><body><p>page</p></body></html>',
      };
    },
  });

  await crawl(ctx);
  const crawled = ctx.endpoints.filter((endpoint) => endpoint.url.includes('/archive/'));
  assert.equal(crawled.length, 20, 'every sitemap URL was crawled');
});

test('sitemap discovery is skipped when the option is off', async () => {
  const ctx = makeContext({ useSitemap: false });
  await crawl(ctx);
  assert.ok(
    !ctx.http.requests.some((request) => request.purpose === 'sitemap'),
    'no sitemap request was made',
  );
});

test('hitting the page limit is reported with what was left uncrawled', async () => {
  const ctx = makeContext({ maxPages: 3 });
  await crawl(ctx);
  const messages = ctx.scan.log.map((entry) => entry.message);
  assert.ok(
    messages.some((message) => /Page limit reached \(3\)/.test(message)),
    `the page limit was reported, got: ${messages.join(' | ')}`,
  );
});
