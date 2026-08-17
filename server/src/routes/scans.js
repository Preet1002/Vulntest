/**
 * Scan API.
 *
 *   POST /api/scans                 start a scan
 *   GET  /api/scans                 list recent scans (summaries)
 *   GET  /api/scans/:id             full scan record
 *   GET  /api/scans/:id/status      progress snapshot
 *   GET  /api/scans/:id/findings    findings, with filters
 *   GET  /api/scans/:id/endpoints   endpoint inventory, with filters
 *   GET  /api/scans/:id/events      Server-Sent Events progress stream
 *   POST /api/scans/:id/stop        stop a running scan
 */
import { Router } from 'express';
import { startScan, stopScan } from '../services/scanManager.js';
import { scanStore, summarize, isTerminal } from '../services/scanStore.js';
import { validateTarget } from '../security/targetPolicy.js';
import { validateScanRequest } from '../middleware/validateScanRequest.js';
import { scanLimiter } from '../middleware/rateLimit.js';
import { DEFAULT_SCAN_CONFIG, HARD_LIMITS, SEVERITY_ORDER, SERVER_CONFIG } from '../config/index.js';
import { logger } from '../utils/logger.js';

export const scansRouter = Router();

/** Wrap an async handler so rejections reach the error middleware. */
const wrap = (handler) => (req, res, next) => Promise.resolve(handler(req, res, next)).catch(next);

// --- start / stop -----------------------------------------------------------

scansRouter.post(
  '/',
  scanLimiter,
  validateScanRequest,
  wrap(async (req, res) => {
    const scan = await startScan({
      target: req.body.target,
      config: req.body.config,
      authorized: req.body.authorized,
    });
    logger.info('scan started', { id: scan.id, target: scan.target });
    res.status(201).json({ scan: summarize(scan), config: scan.config });
  }),
);

scansRouter.post(
  '/:id/stop',
  wrap(async (req, res) => {
    const scan = stopScan(req.params.id);
    res.json({ scan: summarize(scan) });
  }),
);

// --- reads ------------------------------------------------------------------

scansRouter.get('/', (_req, res) => {
  res.json({ scans: scanStore.list() });
});

scansRouter.get('/:id', (req, res) => {
  const scan = scanStore.require(req.params.id);
  res.json({ scan: fullScan(scan) });
});

scansRouter.get('/:id/status', (req, res) => {
  const scan = scanStore.require(req.params.id);
  res.json({
    id: scan.id,
    status: scan.status,
    phase: scan.phase,
    progress: scan.progress,
    currentUrl: scan.currentUrl,
    statistics: scan.statistics,
    error: scan.error,
    finished: isTerminal(scan.status),
    log: scan.log.slice(-25),
  });
});

scansRouter.get('/:id/findings', (req, res) => {
  const scan = scanStore.require(req.params.id);
  const { severity, type, confidence, parameter } = req.query;

  let findings = [...scan.findings];
  if (severity) findings = findings.filter((f) => f.severity.toLowerCase() === String(severity).toLowerCase());
  if (type) findings = findings.filter((f) => f.type.toLowerCase().includes(String(type).toLowerCase()));
  if (confidence) findings = findings.filter((f) => f.confidence.toLowerCase() === String(confidence).toLowerCase());
  if (parameter) findings = findings.filter((f) => (f.parameter || '').toLowerCase() === String(parameter).toLowerCase());

  findings.sort(
    (a, b) => SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity),
  );
  res.json({ findings, total: findings.length });
});

scansRouter.get('/:id/endpoints', (req, res) => {
  const scan = scanStore.require(req.params.id);
  const { method, status, hasParameters, hasForms, vulnerable, q } = req.query;

  let endpoints = [...scan.endpoints];
  if (method) endpoints = endpoints.filter((e) => e.method === String(method).toUpperCase());
  if (status) endpoints = endpoints.filter((e) => String(e.statusCode) === String(status));
  if (hasParameters === 'true') endpoints = endpoints.filter((e) => e.parameters.length > 0);
  if (hasForms === 'true') endpoints = endpoints.filter((e) => e.forms.length > 0);
  if (vulnerable === 'true') endpoints = endpoints.filter((e) => e.vulnerable);
  if (q) {
    const needle = String(q).toLowerCase();
    endpoints = endpoints.filter((e) => e.url.toLowerCase().includes(needle));
  }

  res.json({ endpoints, total: endpoints.length });
});

// --- live progress (SSE) ----------------------------------------------------

scansRouter.get('/:id/events', (req, res) => {
  const scan = scanStore.require(req.params.id);

  res.writeHead(200, {
    'Content-Type': 'text/event-stream; charset=utf-8',
    'Cache-Control': 'no-cache, no-transform',
    Connection: 'keep-alive',
    'X-Accel-Buffering': 'no',
  });
  res.flushHeaders?.();

  const send = (event) => {
    res.write(`event: ${event.type}\n`);
    res.write(`data: ${JSON.stringify(event)}\n\n`);
  };

  // Snapshot first so a client that connects late is immediately consistent.
  send({
    type: 'snapshot',
    at: new Date().toISOString(),
    scan: fullScan(scan),
  });

  if (isTerminal(scan.status)) {
    send({ type: 'done', status: scan.status, statistics: scan.statistics, at: new Date().toISOString() });
    res.end();
    return;
  }

  const unsubscribe = scanStore.subscribe(scan.id, send);
  const heartbeat = setInterval(() => res.write(': keep-alive\n\n'), 20_000);

  const close = () => {
    clearInterval(heartbeat);
    unsubscribe();
    res.end();
  };
  req.on('close', close);
  req.on('error', close);
});

// --- helpers ----------------------------------------------------------------

function fullScan(scan) {
  return {
    ...summarize(scan),
    currentUrl: scan.currentUrl,
    config: scan.config,
    findings: scan.findings,
    endpoints: scan.endpoints,
    log: scan.log,
  };
}

// --- configuration & target pre-validation ---------------------------------

export const metaRouter = Router();

metaRouter.get('/config', (_req, res) => {
  res.json({
    defaults: DEFAULT_SCAN_CONFIG,
    limits: HARD_LIMITS,
    // Surfaced so the dashboard can warn that the SSRF guard is relaxed.
    allowPrivateTargets: SERVER_CONFIG.allowPrivateTargets,
  });
});

metaRouter.post(
  '/validate-target',
  wrap(async (req, res) => {
    const { url } = await validateTarget(req.body?.target);
    res.json({ valid: true, target: url.href, origin: url.origin });
  }),
);
