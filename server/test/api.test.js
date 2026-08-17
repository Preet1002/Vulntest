/**
 * API-level tests. The app is bound to an ephemeral local port; every request
 * here is to our own API, and each scan attempt is expected to be *rejected*
 * before any outbound traffic happens.
 */
import test, { after, before } from 'node:test';
import assert from 'node:assert/strict';
import { createApp } from '../src/app.js';

let server;
let base;

before(async () => {
  server = createApp().listen(0, '127.0.0.1');
  await new Promise((resolve) => server.once('listening', resolve));
  base = `http://127.0.0.1:${server.address().port}`;
});

after(() => server?.close());

const post = (path, body) =>
  fetch(`${base}${path}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });

test('health endpoint responds', async () => {
  const response = await fetch(`${base}/api/health`);
  assert.equal(response.status, 200);
  assert.equal((await response.json()).status, 'ok');
});

test('scans require an explicit authorization confirmation', async () => {
  const response = await post('/api/scans', { target: 'https://example.com' });
  assert.equal(response.status, 403);
  assert.equal((await response.json()).error.code, 'authorization_not_confirmed');
});

test('localhost, private and metadata targets are refused', async () => {
  const targets = [
    'http://localhost:3000',
    'http://127.0.0.1/',
    'http://169.254.169.254/latest/meta-data/',
    'http://10.0.0.1/',
    'http://192.168.1.1/',
    'http://[::1]/',
    'http://db.internal/',
  ];

  for (const target of targets) {
    const response = await post('/api/scans', { target, authorized: true });
    assert.equal(response.status, 400, `${target} should be rejected`);
    assert.equal((await response.json()).error.code, 'blocked_target', target);
  }
});

test('non-web schemes, ports and malformed URLs are refused', async () => {
  const cases = [
    ['file:///etc/passwd', 'blocked_target'],
    ['ftp://example.com/', 'blocked_target'],
    ['https://example.com:22/', 'blocked_target'],
    ['https://user:pass@example.com/', 'blocked_target'],
    ['not a url', 'invalid_target'],
    ['', 'missing_target'],
  ];

  for (const [target, code] of cases) {
    const response = await post('/api/scans', { target, authorized: true });
    assert.ok(response.status >= 400, `${target} should fail`);
    assert.equal((await response.json()).error.code, code, target);
  }
});

test('validate-target rejects internal hosts without starting a scan', async () => {
  const response = await post('/api/validate-target', { target: 'http://192.168.0.10' });
  assert.equal(response.status, 400);
  assert.equal((await response.json()).error.code, 'blocked_target');
});

test('unknown scans return 404 and unknown routes are handled', async () => {
  const scan = await fetch(`${base}/api/scans/scan_missing`);
  assert.equal(scan.status, 404);
  assert.equal((await scan.json()).error.code, 'scan_not_found');

  const route = await fetch(`${base}/api/nope`);
  assert.equal(route.status, 404);
});

test('scan configuration limits are published for the dashboard', async () => {
  const response = await fetch(`${base}/api/config`);
  const { defaults, limits } = await response.json();
  assert.equal(defaults.maxPages, 100);
  assert.equal(limits.maxPages, 250);
});

test('oversized request bodies are rejected', async () => {
  const response = await post('/api/scans', { target: `https://example.com/${'a'.repeat(40_000)}` });
  assert.equal(response.status, 413);
});
