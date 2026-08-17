/**
 * Runtime state for a single scan.
 *
 * The crawler and every detection module receive a ScanContext and go through
 * it for HTTP access, cancellation, findings and progress reporting. That keeps
 * the modules themselves free of transport and bookkeeping concerns.
 */
import { HARD_LIMITS } from '../config/index.js';
import { findingId, endpointId } from '../utils/ids.js';
import { clampEvidence } from '../utils/text.js';
import { dedupeKey } from '../utils/url.js';
import { ScannerHttpClient } from './httpClient.js';
import { scanStore, SCAN_STATUS, appendLog } from './scanStore.js';

/**
 * Identity of a finding, independent of the probe value that produced it.
 * A finding URL carries the random canary, so the query string is dropped
 * whenever a parameter names the injection point.
 */
/** `METHOD origin/path` - the query string is deliberately excluded. */
function pathIndexKey(method, url) {
  try {
    const parsed = new URL(url instanceof URL ? url.href : String(url));
    return `${method} ${parsed.origin}${parsed.pathname}`;
  } catch {
    return `${method} ${url}`;
  }
}

function findingIdentity(input) {
  const url = input.url instanceof URL ? input.url.href : String(input.url);
  if (!input.parameter) return dedupeKey(url);
  try {
    const parsed = new URL(url);
    return `${parsed.origin}${parsed.pathname}|${input.parameter}`;
  } catch {
    return `${url}|${input.parameter}`;
  }
}

export class ScanContext {
  /**
   * @param {object} scan the stored scan record
   * @param {import('../security/targetPolicy.js').TargetPolicy} policy
   */
  constructor(scan, policy) {
    this.scan = scan;
    this.policy = policy;
    this.config = scan.config;
    this.stopped = false;
    this.stopReason = null;
    this.deadline = Date.now() + scan.config.maxScanDurationMs;
    this.robots = null;

    this.endpointsByKey = new Map();
    // Secondary index ignoring the query string, so a finding whose URL carries
    // a probe value still resolves back to the endpoint it came from.
    this.endpointsByPath = new Map();
    this.findingKeys = new Set();

    this.http = new ScannerHttpClient({
      policy,
      config: scan.config,
      shouldStop: () => this.shouldStop(),
      onRequest: (info) => this.recordRequest(info),
    });
  }

  // --- lifecycle -----------------------------------------------------------

  shouldStop() {
    if (this.stopped) return true;
    if (Date.now() > this.deadline) {
      this.stop('maximum scan duration reached');
      return true;
    }
    if (this.http && this.http.budgetExhausted) {
      this.stop('request budget reached');
      return true;
    }
    return false;
  }

  stop(reason = 'stopped by user') {
    if (this.stopped) return;
    this.stopped = true;
    this.stopReason = reason;
    this.log('warn', `Scan stopping: ${reason}.`);
  }

  setStatus(status) {
    this.scan.status = status;
    scanStore.emit(this.scan.id, 'status', { status, phase: this.scan.phase });
  }

  setPhase(phase, message) {
    this.scan.phase = phase;
    if (message) this.log('info', message);
    scanStore.emit(this.scan.id, 'status', { status: this.scan.status, phase });
  }

  /** @param {number} value 0..100 */
  setProgress(value, current = null) {
    const clamped = Math.max(0, Math.min(100, Math.round(value)));
    this.scan.progress = clamped;
    if (current !== null) this.scan.currentUrl = current;
    scanStore.emit(this.scan.id, 'progress', {
      progress: clamped,
      currentUrl: this.scan.currentUrl,
      statistics: this.scan.statistics,
      phase: this.scan.phase,
      status: this.scan.status,
    });
  }

  log(level, message) {
    appendLog(this.scan, level, message);
    scanStore.emit(this.scan.id, 'log', { level, message });
  }

  // --- telemetry -----------------------------------------------------------

  /** Called by the HTTP layer after every request (public so tests can drive it). */
  recordRequest(info) {
    const stats = this.scan.statistics;
    stats.requests = this.http.requestCount;
    if (info.error) stats.errors += 1;
    if (info.status) {
      const bucket = String(info.status);
      stats.byStatusCode[bucket] = (stats.byStatusCode[bucket] || 0) + 1;
    }
  }

  // --- endpoints -----------------------------------------------------------

  /**
   * Add (or merge into) the endpoint inventory.
   * @returns {object} the stored endpoint record
   */
  addEndpoint(input) {
    const method = (input.method || 'GET').toUpperCase();
    const key = `${method} ${dedupeKey(input.url)}`;
    const existing = this.endpointsByKey.get(key);

    if (existing) {
      // Merge newly learned details into the record we already have.
      const parameters = new Set([...existing.parameters, ...(input.parameters || [])]);
      existing.parameters = [...parameters];
      if (input.statusCode != null) existing.statusCode = input.statusCode;
      if (input.contentType) existing.contentType = input.contentType;
      if (input.title && !existing.title) existing.title = input.title;
      if (input.forms?.length) {
        const seen = new Set(existing.forms.map((form) => JSON.stringify(form)));
        for (const form of input.forms) {
          const serialized = JSON.stringify(form);
          if (!seen.has(serialized)) {
            existing.forms.push(form);
            seen.add(serialized);
          }
        }
      }
      scanStore.emit(this.scan.id, 'endpoint', { endpoint: existing, updated: true });
      return existing;
    }

    const endpoint = {
      id: endpointId(),
      url: input.url instanceof URL ? input.url.href : String(input.url),
      method,
      source: input.source || 'link',
      parameters: [...new Set(input.parameters || [])],
      forms: input.forms || [],
      statusCode: input.statusCode ?? null,
      contentType: input.contentType || '',
      title: input.title || '',
      depth: input.depth ?? null,
      discoveredAt: new Date().toISOString(),
      vulnerable: false,
      findingCount: 0,
    };

    this.endpointsByKey.set(key, endpoint);
    const pathKey = pathIndexKey(method, endpoint.url);
    if (!this.endpointsByPath.has(pathKey)) this.endpointsByPath.set(pathKey, []);
    this.endpointsByPath.get(pathKey).push(endpoint);
    this.scan.endpoints.push(endpoint);
    this.scan.statistics.endpoints = this.scan.endpoints.length;
    scanStore.emit(this.scan.id, 'endpoint', { endpoint, updated: false });
    return endpoint;
  }

  get endpoints() {
    return this.scan.endpoints;
  }

  // --- findings ------------------------------------------------------------

  /**
   * Record a finding. Duplicate findings (same type + url + parameter, or an
   * explicit `dedupeKey`) are dropped so a site-wide issue is reported once.
   * @returns {object|null} the stored finding, or null when suppressed
   */
  addFinding(input) {
    const key = input.dedupeKey || `${input.type}|${findingIdentity(input)}`;
    if (this.findingKeys.has(key)) return null;
    if (this.scan.findings.length >= HARD_LIMITS.maxFindings) return null;
    this.findingKeys.add(key);

    const finding = {
      id: findingId(),
      type: input.type,
      severity: input.severity,
      confidence: input.confidence,
      url: input.url instanceof URL ? input.url.href : String(input.url),
      parameter: input.parameter || null,
      method: (input.method || 'GET').toUpperCase(),
      description: input.description || '',
      evidence: clampEvidence(input.evidence || ''),
      recommendation: input.recommendation || '',
      references: input.references || [],
      status: 'Open',
      timestamp: new Date().toISOString(),
    };

    this.scan.findings.push(finding);

    const stats = this.scan.statistics;
    stats.vulnerabilities = this.scan.findings.length;
    stats.bySeverity[finding.severity] = (stats.bySeverity[finding.severity] || 0) + 1;
    stats.byType[finding.type] = (stats.byType[finding.type] || 0) + 1;

    // Flag the endpoint(s) this finding belongs to so the explorer can filter
    // on it. The exact URL rarely matches - probe values differ - so fall back
    // to every endpoint sharing the same method and path.
    const exact = this.endpointsByKey.get(`${finding.method} ${dedupeKey(finding.url)}`);
    const matches = exact
      ? [exact]
      : this.endpointsByPath.get(pathIndexKey(finding.method, finding.url)) || [];
    for (const endpoint of matches) {
      endpoint.vulnerable = true;
      endpoint.findingCount += 1;
      scanStore.emit(this.scan.id, 'endpoint', { endpoint, updated: true });
    }

    this.log('finding', `${finding.severity}: ${finding.type} at ${finding.url}`);
    scanStore.emit(this.scan.id, 'finding', { finding });
    return finding;
  }

  finish(status = SCAN_STATUS.COMPLETED, error = null) {
    this.scan.status = status;
    this.scan.completedAt = new Date().toISOString();
    this.scan.statistics.durationMs = new Date(this.scan.completedAt) - new Date(this.scan.startedAt);
    this.scan.statistics.requests = this.http.requestCount;
    this.scan.currentUrl = null;
    this.scan.error = error;
    this.scan.progress = status === SCAN_STATUS.COMPLETED ? 100 : this.scan.progress;
    scanStore.emit(this.scan.id, 'done', {
      status,
      error,
      statistics: this.scan.statistics,
      progress: this.scan.progress,
      completedAt: this.scan.completedAt,
    });
  }
}
