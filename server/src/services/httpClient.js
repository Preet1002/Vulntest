/**
 * The single outbound HTTP layer.
 *
 * Nothing in the crawler or the detection modules is allowed to call axios (or
 * fetch) directly - every request goes through here so that timeouts, rate
 * limiting, the scope policy, the SSRF guard, response size caps and the
 * request budget are applied uniformly.
 */
import http from 'node:http';
import https from 'node:https';
import axios from 'axios';
import { SCANNER_USER_AGENT, HARD_LIMITS } from '../config/index.js';
import { safeLookup } from '../security/ssrfGuard.js';
import { BlockedTargetError } from '../utils/errors.js';
import { RateLimiter } from './rateLimiter.js';

/**
 * Agents are shared process-wide. `lookup: safeLookup` is the important part:
 * the address the socket connects to is validated at connect time, which is
 * what protects against DNS rebinding.
 */
const agentOptions = {
  keepAlive: true,
  maxSockets: HARD_LIMITS.concurrency * 4,
  timeout: HARD_LIMITS.requestTimeoutMs,
  lookup: safeLookup,
};

const httpAgent = new http.Agent(agentOptions);
const httpsAgent = new https.Agent(agentOptions);

const TEXTUAL_CONTENT = /(text\/|json|javascript|xml|x-www-form-urlencoded|\+xml|\+json)/i;

export class ScannerHttpClient {
  /**
   * @param {object} options
   * @param {import('../security/targetPolicy.js').TargetPolicy} options.policy
   * @param {object} options.config resolved scan configuration
   * @param {() => boolean} [options.shouldStop] cooperative cancellation hook
   * @param {(info: object) => void} [options.onRequest] per-request telemetry
   */
  constructor({ policy, config, shouldStop = () => false, onRequest = () => {} }) {
    this.policy = policy;
    this.config = config;
    this.shouldStop = shouldStop;
    this.onRequest = onRequest;
    this.limiter = new RateLimiter({
      concurrency: config.concurrency,
      delayMs: config.delayMs,
    });
    this.requestCount = 0;
    this.errorCount = 0;
    this.bytesReceived = 0;
  }

  get budgetExhausted() {
    return this.requestCount >= this.config.maxRequests;
  }

  /**
   * Perform one request, following redirects manually so that every hop is
   * re-validated against the scope policy.
   *
   * Never throws for network-level problems: callers get `{ ok: false, error }`
   * so a single dead link cannot abort a scan.
   *
   * @returns {Promise<{
   *   ok: boolean, url: string, requestedUrl: string, method: string,
   *   status: number|null, headers: object, body: string, contentType: string,
   *   bytes: number, timeMs: number, redirects: string[], error: string|null,
   *   truncated: boolean
   * }>}
   */
  async request({ url, method = 'GET', headers = {}, data = null, purpose = 'crawl' } = {}) {
    const requestedUrl = url instanceof URL ? url.href : String(url);
    const result = {
      ok: false,
      url: requestedUrl,
      requestedUrl,
      method: method.toUpperCase(),
      status: null,
      headers: {},
      body: '',
      contentType: '',
      bytes: 0,
      timeMs: 0,
      redirects: [],
      error: null,
      truncated: false,
    };

    if (this.shouldStop()) {
      result.error = 'scan stopped';
      return result;
    }
    if (this.budgetExhausted) {
      result.error = 'request budget exhausted';
      return result;
    }

    try {
      this.policy.assertAllowed(requestedUrl);
    } catch (error) {
      result.error = error.message;
      return result;
    }

    const started = Date.now();
    const maxRedirects = Number.isInteger(this.config.maxRedirects)
      ? this.config.maxRedirects
      : HARD_LIMITS.maxRedirects;
    let currentUrl = requestedUrl;
    let currentMethod = result.method;
    let currentData = data;
    let hops = 0;

    try {
      for (;;) {
        if (this.shouldStop()) {
          result.error = 'scan stopped';
          return result;
        }

        // eslint-disable-next-line no-await-in-loop
        const response = await this.limiter.schedule(() => {
          this.requestCount += 1;
          return axios.request({
            url: currentUrl,
            method: currentMethod,
            data: currentData ?? undefined,
            timeout: this.config.requestTimeoutMs,
            maxRedirects: 0, // handled below so each hop can be validated
            maxContentLength: this.config.maxResponseBytes,
            maxBodyLength: this.config.maxResponseBytes,
            responseType: 'text',
            transformResponse: [(body) => body],
            decompress: true,
            validateStatus: () => true,
            httpAgent,
            httpsAgent,
            headers: {
              'User-Agent': SCANNER_USER_AGENT,
              Accept: 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
              'Accept-Language': 'en-US,en;q=0.9',
              'X-Scanner': 'authorized-vulnerability-scan',
              ...headers,
            },
          });
        });

        result.status = response.status;
        result.headers = response.headers?.toJSON ? response.headers.toJSON() : { ...response.headers };
        result.contentType = String(result.headers['content-type'] || '');
        result.url = currentUrl;

        const location = result.headers.location;
        const isRedirect = response.status >= 300 && response.status < 400 && location;
        if (!isRedirect) {
          const body = typeof response.data === 'string' ? response.data : '';
          result.body = TEXTUAL_CONTENT.test(result.contentType) || !result.contentType ? body : '';
          result.bytes = Buffer.byteLength(body || '', 'utf8');
          result.truncated = result.bytes >= this.config.maxResponseBytes;
          result.ok = true;
          break;
        }

        // --- redirect handling: re-validate the destination before following ---
        hops += 1;
        if (hops > maxRedirects) {
          result.error = `stopped after ${maxRedirects} redirects`;
          break;
        }

        let nextUrl;
        try {
          nextUrl = new URL(location, currentUrl).href;
        } catch {
          result.error = `invalid redirect target: ${location}`;
          break;
        }

        const verdict = this.policy.check(nextUrl);
        if (!verdict.allowed) {
          result.ok = true; // the response itself is valid, we just stop here
          result.error = `redirect to ${nextUrl} not followed: ${verdict.reason}`;
          result.body = '';
          break;
        }

        result.redirects.push(nextUrl);
        currentUrl = nextUrl;
        // 303, and 301/302 in practice, downgrade to GET without a body.
        if (response.status === 303 || ((response.status === 301 || response.status === 302) && currentMethod !== 'GET')) {
          currentMethod = 'GET';
          currentData = null;
        }
      }
    } catch (error) {
      this.errorCount += 1;
      if (error instanceof BlockedTargetError) {
        result.error = error.message;
      } else if (error.code === 'ECONNABORTED' || error.code === 'ETIMEDOUT') {
        result.error = `timeout after ${this.config.requestTimeoutMs}ms`;
      } else if (error.code === 'ERR_FR_MAX_CONTENT_LENGTH_EXCEEDED') {
        result.error = 'response exceeded the maximum allowed size';
        result.truncated = true;
      } else {
        result.error = error.code ? `${error.code}: ${error.message}` : error.message;
      }
    }

    result.timeMs = Date.now() - started;
    this.bytesReceived += result.bytes;
    this.onRequest({
      url: result.url,
      method: result.method,
      status: result.status,
      purpose,
      timeMs: result.timeMs,
      error: result.error,
    });
    return result;
  }

  get(url, options = {}) {
    return this.request({ ...options, url, method: 'GET' });
  }

  /** Submit a form body as application/x-www-form-urlencoded. */
  postForm(url, fields, options = {}) {
    const body = new URLSearchParams(fields).toString();
    return this.request({
      ...options,
      url,
      method: 'POST',
      data: body,
      headers: { 'Content-Type': 'application/x-www-form-urlencoded', ...(options.headers || {}) },
    });
  }
}
