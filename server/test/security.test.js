import test from 'node:test';
import assert from 'node:assert/strict';
import { classifyIp } from '../src/security/ipRules.js';
import { assertSafeHostname, safeLookup } from '../src/security/ssrfGuard.js';
import { TargetPolicy } from '../src/security/targetPolicy.js';
import { dedupeKey, signatureKey, normalizeUrl, looksLikeCrawlTrap } from '../src/utils/url.js';
import { parseRobots, RobotsPolicy } from '../src/services/robots.js';
import { similarity } from '../src/utils/text.js';

test('private, loopback and metadata addresses are blocked', () => {
  const blocked = [
    '127.0.0.1', '127.1.1.1', '10.0.0.5', '172.16.0.1', '172.31.255.255',
    '192.168.1.1', '169.254.169.254', '0.0.0.0', '100.64.0.1', '198.18.0.1',
    '224.0.0.1', '255.255.255.255', '::1', '::', 'fd00:ec2::254', 'fe80::1',
    '::ffff:127.0.0.1', '::ffff:10.0.0.1', '2002:7f00:0001::', '64:ff9b::7f00:1',
  ];
  for (const ip of blocked) {
    assert.equal(classifyIp(ip).blocked, true, `${ip} should be blocked`);
  }
});

test('public addresses are allowed', () => {
  for (const ip of ['8.8.8.8', '1.1.1.1', '93.184.216.34', '2606:4700:4700::1111']) {
    assert.equal(classifyIp(ip).blocked, false, `${ip} should be allowed`);
  }
});

test('internal hostnames are rejected before DNS', () => {
  for (const host of ['localhost', 'router.local', 'db.internal', 'metadata.google.internal', 'intranet']) {
    assert.throws(() => assertSafeHostname(host), /not allowed|internal|public hostname/i, host);
  }
  assert.equal(assertSafeHostname('example.com'), 'example.com');
});

test('the agent DNS hook refuses a name that resolves to a private address', async () => {
  // safeLookup runs at connect time, which is what closes the DNS-rebinding
  // window: whatever the pre-flight check saw, the socket only ever connects
  // to an address that passed this hook.
  const error = await new Promise((resolve) => {
    safeLookup('localhost', { family: 4 }, (lookupError) => resolve(lookupError));
  });
  assert.ok(error, 'localhost must not resolve for the scanner');
  assert.match(error.message, /Blocked connection|not allowed|loopback/i);
});

test('target policy keeps requests inside the approved origin', () => {
  const policy = new TargetPolicy(new URL('https://target.example/app'));

  assert.equal(policy.isAllowed('https://target.example/other'), true);
  assert.equal(policy.isAllowed('https://evil.example/'), false);
  assert.equal(policy.isAllowed('https://sub.target.example/'), false);
  assert.equal(policy.isAllowed('https://target.example:8443/'), false);
  assert.equal(policy.isAllowed('ftp://target.example/'), false);
  assert.throws(() => policy.assertAllowed('https://evil.example/'), /refused/);
});

test('target policy can opt into subdomains', () => {
  const policy = new TargetPolicy(new URL('https://target.example/'), { allowSubdomains: true });
  assert.equal(policy.isAllowed('https://api.target.example/v1'), true);
  assert.equal(policy.isAllowed('https://nottarget.example/'), false);
});

test('URL dedupe ignores tracking parameters and ordering', () => {
  const a = dedupeKey('https://x.example/p?b=2&a=1&utm_source=news');
  const b = dedupeKey('https://x.example/p?a=1&b=2&fbclid=xyz');
  assert.equal(a, b);
  assert.notEqual(dedupeKey('https://x.example/p?a=1'), dedupeKey('https://x.example/p?a=2'));
});

test('signature key groups value variants of the same endpoint', () => {
  assert.equal(
    signatureKey('https://x.example/cal?month=1&year=2024'),
    signatureKey('https://x.example/cal?month=12&year=2030'),
  );
});

test('crawl traps are detected', () => {
  assert.equal(looksLikeCrawlTrap('https://x.example/a/a/a/b'), true);
  assert.equal(looksLikeCrawlTrap('https://x.example/1/2/3/4/5/6/7/8/9/10/11/12/13'), true);
  assert.equal(looksLikeCrawlTrap('https://x.example/products/shoes/running'), false);
});

test('non-http schemes are not crawlable', () => {
  for (const href of ['mailto:a@b.example', 'javascript:alert(1)', 'tel:+1234', '#anchor', 'data:text/html,x']) {
    assert.equal(normalizeUrl(href, 'https://x.example/'), null, href);
  }
  assert.equal(normalizeUrl('/a', 'https://x.example/b').href, 'https://x.example/a');
});

test('robots.txt rules are honoured with longest-match precedence', () => {
  const robots = new RobotsPolicy(
    parseRobots(['User-agent: *', 'Disallow: /private', 'Allow: /private/public', 'Crawl-delay: 2'].join('\n')),
  );
  assert.equal(robots.isAllowed('https://x.example/private/secret'), false);
  assert.equal(robots.isAllowed('https://x.example/private/public/page'), true);
  assert.equal(robots.isAllowed('https://x.example/open'), true);
  assert.equal(robots.crawlDelayMs, 2000);
});

test('body similarity separates identical, noisy and different pages', () => {
  const base = '<html><body><h1>Catalogue</h1><ul><li>Runner</li><li>Sandal</li><li>Boot</li></ul></body></html>';
  const noisy = base.replace('Catalogue', 'Catalogue') + '<!-- 2024-01-01T10:00:00 -->';
  const different = '<html><body><h1>Catalogue</h1><p>No items matched.</p></body></html>';

  assert.equal(similarity(base, base), 1);
  assert.ok(similarity(base, noisy) > 0.9, 'timestamp-only change should stay similar');
  assert.ok(similarity(base, different) < 0.75, 'content change should drop similarity');
});
