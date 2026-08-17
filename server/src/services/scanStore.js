/**
 * In-memory scan registry plus the event bus that backs Server-Sent Events.
 *
 * Long term persistence deliberately lives in the browser (localStorage) - the
 * backend only keeps the most recent scans so a reload or a second dashboard
 * tab can re-attach to a running scan.
 */
import { EventEmitter } from 'node:events';
import { SERVER_CONFIG, HARD_LIMITS } from '../config/index.js';
import { AppError } from '../utils/errors.js';

export const SCAN_STATUS = {
  QUEUED: 'queued',
  CRAWLING: 'crawling',
  SCANNING: 'scanning',
  COMPLETED: 'completed',
  STOPPED: 'stopped',
  FAILED: 'failed',
};

const TERMINAL_STATUSES = new Set([SCAN_STATUS.COMPLETED, SCAN_STATUS.STOPPED, SCAN_STATUS.FAILED]);

export const isTerminal = (status) => TERMINAL_STATUSES.has(status);

class ScanStore {
  constructor() {
    this.scans = new Map();
    this.emitter = new EventEmitter();
    // One listener per connected SSE client, per scan.
    this.emitter.setMaxListeners(200);
  }

  create(scan) {
    this.scans.set(scan.id, scan);
    this.#prune();
    return scan;
  }

  get(id) {
    return this.scans.get(id) || null;
  }

  require(id) {
    const scan = this.get(id);
    if (!scan) {
      throw new AppError(`No scan found with id "${id}".`, { status: 404, code: 'scan_not_found' });
    }
    return scan;
  }

  list() {
    return [...this.scans.values()]
      .sort((a, b) => new Date(b.startedAt) - new Date(a.startedAt))
      .map((scan) => summarize(scan));
  }

  activeCount() {
    return [...this.scans.values()].filter((scan) => !isTerminal(scan.status)).length;
  }

  /** Publish an event to every SSE subscriber of this scan. */
  emit(scanId, type, payload = {}) {
    this.emitter.emit(scanId, { type, ...payload, at: new Date().toISOString() });
  }

  subscribe(scanId, listener) {
    this.emitter.on(scanId, listener);
    return () => this.emitter.off(scanId, listener);
  }

  /** Drop the oldest finished scans once the retention limit is passed. */
  #prune() {
    const finished = [...this.scans.values()]
      .filter((scan) => isTerminal(scan.status))
      .sort((a, b) => new Date(a.startedAt) - new Date(b.startedAt));

    let excess = this.scans.size - SERVER_CONFIG.scanRetention;
    while (excess > 0 && finished.length > 0) {
      const oldest = finished.shift();
      this.scans.delete(oldest.id);
      this.emitter.removeAllListeners(oldest.id);
      excess -= 1;
    }
  }
}

/** Blank statistics block - shared by the scan record and the API responses. */
export const emptyStatistics = () => ({
  pages: 0,
  endpoints: 0,
  requests: 0,
  vulnerabilities: 0,
  errors: 0,
  bySeverity: { Critical: 0, High: 0, Medium: 0, Low: 0, Info: 0 },
  byType: {},
  byStatusCode: {},
  durationMs: 0,
});

/** Compact form used by list endpoints and the history view. */
export function summarize(scan) {
  return {
    id: scan.id,
    target: scan.target,
    origin: scan.origin,
    status: scan.status,
    phase: scan.phase,
    progress: scan.progress,
    startedAt: scan.startedAt,
    completedAt: scan.completedAt,
    statistics: scan.statistics,
    error: scan.error,
  };
}

/** Append to the bounded activity log kept with the scan. */
export function appendLog(scan, level, message) {
  scan.log.push({ at: new Date().toISOString(), level, message });
  if (scan.log.length > HARD_LIMITS.maxLogEntries) {
    scan.log.splice(0, scan.log.length - HARD_LIMITS.maxLogEntries);
  }
}

export const scanStore = new ScanStore();
