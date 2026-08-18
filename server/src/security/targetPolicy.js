/**
 * Target scope policy.
 *
 * A scan is pinned to exactly one origin (optionally its subdomains). Every URL
 * the crawler or a detection module wants to request is checked against the
 * policy, which is what keeps the backend from behaving like a general purpose
 * URL fetcher.
 */
import { assertSafeUrl } from './ssrfGuard.js';
import { HARD_LIMITS } from '../config/index.js';
import { AppError, BlockedTargetError } from '../utils/errors.js';

/** `www.example.com` and `example.com` are the same site, not two targets. */
const withoutWww = (host) => (host.startsWith('www.') ? host.slice(4) : host);

export class TargetPolicy {
  /**
   * @param {URL} targetUrl validated target
   * @param {{allowSubdomains?: boolean}} options
   */
  constructor(targetUrl, { allowSubdomains = false } = {}) {
    this.target = targetUrl;
    this.origin = targetUrl.origin;
    this.hostname = targetUrl.hostname.toLowerCase();
    this.apexHostname = withoutWww(this.hostname);
    this.allowSubdomains = allowSubdomains;
  }

  /**
   * Re-pin the policy after the start URL redirected somewhere else - the
   * apex -> www hop that most sites perform. Without this the scan stays
   * pinned to a host that only ever answers with a redirect, and the crawl
   * ends after a single page.
   * @param {URL} url the URL the seed request actually landed on
   */
  rebind(url) {
    this.target = url;
    this.origin = url.origin;
    this.hostname = url.hostname.toLowerCase();
    this.apexHostname = withoutWww(this.hostname);
  }

  /** @returns {{allowed: boolean, reason: string|null}} */
  check(input) {
    let url;
    try {
      url = input instanceof URL ? input : new URL(String(input));
    } catch {
      return { allowed: false, reason: 'not a valid absolute URL' };
    }

    if (url.protocol !== 'http:' && url.protocol !== 'https:') {
      return { allowed: false, reason: `unsupported protocol ${url.protocol}` };
    }
    if (url.href.length > HARD_LIMITS.maxUrlLength) {
      return { allowed: false, reason: 'URL exceeds the maximum length' };
    }

    const host = url.hostname.toLowerCase();
    // `www.` is a presentation detail of the same site, so both spellings are
    // in scope regardless of which one the operator typed as the target.
    const sameSite = host === this.hostname || withoutWww(host) === this.apexHostname;
    const isSubdomain = this.allowSubdomains && withoutWww(host).endsWith(`.${this.apexHostname}`);
    if (!sameSite && !isSubdomain) {
      return { allowed: false, reason: `outside the approved target scope (${this.origin})` };
    }

    // Same site but a different port or scheme is still a different origin.
    if (sameSite && url.origin !== this.origin) {
      const samePort = url.port === this.target.port;
      const httpsUpgrade = this.target.protocol === 'http:' && url.protocol === 'https:' && samePort;
      const wwwHop = host !== this.hostname && url.protocol === this.target.protocol && samePort;
      if (!httpsUpgrade && !wwwHop) {
        return { allowed: false, reason: `different origin (${url.origin})` };
      }
    }

    return { allowed: true, reason: null };
  }

  isAllowed(input) {
    return this.check(input).allowed;
  }

  assertAllowed(input) {
    const { allowed, reason } = this.check(input);
    if (!allowed) {
      throw new BlockedTargetError(`Request to ${input} refused: ${reason}.`);
    }
    return true;
  }
}

/**
 * Validate and normalise a user supplied target URL.
 * @returns {Promise<{url: URL, addresses: string[]}>}
 */
export async function validateTarget(rawTarget) {
  if (typeof rawTarget !== 'string' || rawTarget.trim() === '') {
    throw new AppError('A target URL is required.', { code: 'missing_target' });
  }
  const trimmed = rawTarget.trim();
  if (trimmed.length > HARD_LIMITS.maxUrlLength) {
    throw new AppError('The target URL is too long.', { code: 'invalid_target' });
  }

  // Accept "example.com" as a convenience and default it to https.
  const withScheme = /^[a-z][a-z0-9+\-.]*:\/\//i.test(trimmed) ? trimmed : `https://${trimmed}`;

  const { url, addresses } = await assertSafeUrl(withScheme);
  url.hash = '';
  return { url, addresses };
}
