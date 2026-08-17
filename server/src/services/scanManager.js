/**
 * Scan lifecycle: create, run, stop.
 *
 * A scan runs as a detached async task. Progress is published through the store
 * (Server-Sent Events) while the full record stays available over REST.
 */
import { resolveScanConfig, SERVER_CONFIG } from '../config/index.js';
import { TargetPolicy, validateTarget } from '../security/targetPolicy.js';
import { crawl } from '../crawler/crawler.js';
import { runActiveScan } from '../scanner/index.js';
import { AppError } from '../utils/errors.js';
import { scanId } from '../utils/ids.js';
import { logger } from '../utils/logger.js';
import { ScanContext } from './scanContext.js';
import { loadRobots } from './robots.js';
import { scanStore, SCAN_STATUS, emptyStatistics, appendLog, isTerminal } from './scanStore.js';

/** ScanContext instances for currently running scans, keyed by scan id. */
const running = new Map();

/**
 * Validate the target, register the scan and start it in the background.
 * @returns {Promise<object>} the created scan record
 */
export async function startScan({ target, config = {}, authorized = false }) {
  if (authorized !== true) {
    throw new AppError(
      'You must confirm that you are authorized to scan this target before a scan can start.',
      { status: 403, code: 'authorization_not_confirmed' },
    );
  }
  if (scanStore.activeCount() >= SERVER_CONFIG.maxConcurrentScans) {
    throw new AppError(
      `The server is already running ${SERVER_CONFIG.maxConcurrentScans} scan(s). Wait for one to finish or stop it first.`,
      { status: 429, code: 'too_many_scans' },
    );
  }

  const { url, addresses } = await validateTarget(target);
  const resolved = resolveScanConfig(config);

  const scan = {
    id: scanId(),
    target: url.href,
    origin: url.origin,
    status: SCAN_STATUS.QUEUED,
    phase: 'queued',
    progress: 0,
    currentUrl: null,
    config: resolved,
    startedAt: new Date().toISOString(),
    completedAt: null,
    statistics: { ...emptyStatistics(), parametersTested: 0 },
    findings: [],
    endpoints: [],
    log: [],
    error: null,
  };

  scanStore.create(scan);
  appendLog(scan, 'info', `Scan queued for ${url.href} (resolves to ${addresses.slice(0, 3).join(', ')}).`);

  // Deliberately not awaited: the HTTP request returns as soon as the scan is
  // registered, and the dashboard follows progress over SSE.
  void execute(scan, url, resolved);

  return scan;
}

async function execute(scan, url, config) {
  const policy = new TargetPolicy(url, { allowSubdomains: config.allowSubdomains });
  const ctx = new ScanContext(scan, policy);
  running.set(scan.id, ctx);

  try {
    ctx.setStatus(SCAN_STATUS.CRAWLING);
    ctx.setPhase('robots', 'Checking robots.txt.');

    if (config.respectRobots) {
      ctx.robots = await loadRobots(ctx.http, url.origin);
      if (ctx.robots.available) {
        ctx.log('info', `robots.txt loaded: ${ctx.robots.rules.length} rule(s) apply to this scanner.`);
        if (ctx.robots.crawlDelayMs > 0) {
          ctx.http.limiter.setMinimumDelay(ctx.robots.crawlDelayMs);
          ctx.log('info', `Honouring Crawl-delay of ${ctx.robots.crawlDelayMs / 1000}s.`);
        }
        if (!ctx.robots.isAllowed(url)) {
          ctx.log('warn', 'robots.txt disallows the start URL; crawling it anyway as the explicit scan target.');
        }
      } else {
        ctx.log('info', 'No usable robots.txt found - continuing with the configured limits.');
      }
    }

    ctx.setPhase('crawling', `Crawling ${url.href} (max ${config.maxPages} pages, depth ${config.maxDepth}).`);
    await crawl(ctx);

    if (!ctx.stopped) {
      ctx.setStatus(SCAN_STATUS.SCANNING);
      ctx.setPhase('testing', 'Running safe vulnerability checks on discovered parameters.');
      await runActiveScan(ctx);
    }

    if (ctx.stopped) {
      ctx.setPhase('stopped');
      ctx.finish(SCAN_STATUS.STOPPED, ctx.stopReason);
      logger.info('scan stopped', { id: scan.id, reason: ctx.stopReason });
    } else {
      ctx.setPhase('completed');
      ctx.finish(SCAN_STATUS.COMPLETED);
      logger.info('scan completed', {
        id: scan.id,
        pages: scan.statistics.pages,
        endpoints: scan.statistics.endpoints,
        findings: scan.statistics.vulnerabilities,
        requests: scan.statistics.requests,
      });
    }
  } catch (error) {
    logger.error('scan failed', { id: scan.id, error: error.message });
    ctx.log('error', `Scan failed: ${error.message}`);
    ctx.setPhase('failed');
    ctx.finish(SCAN_STATUS.FAILED, error.message);
  } finally {
    running.delete(scan.id);
  }
}

/** Cooperative stop - in-flight requests finish, nothing new is started. */
export function stopScan(id, reason = 'stopped by user') {
  const scan = scanStore.require(id);
  if (isTerminal(scan.status)) return scan;

  const ctx = running.get(id);
  if (ctx) {
    ctx.stop(reason);
  } else {
    scan.status = SCAN_STATUS.STOPPED;
    scan.completedAt = new Date().toISOString();
    scanStore.emit(id, 'done', { status: scan.status, statistics: scan.statistics });
  }
  return scan;
}
