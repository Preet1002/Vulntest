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

export class TargetPolicy {
  /**
   * @param {URL} targetUrl validated target
   * @param {{allowSubdomains?: boolean}} options
   */
  constructor(targetUrl, { allowSubdomains = false } = {}) {
    this.target = targetUrl;
    this.origin = targetUrl.origin;
    this.hostname = targetUrl.hostname.toLowerCase();
    this.allowSubdomains = allowSubdomains;
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
    const sameHost = host === this.hostname;
    const isSubdomain = this.allowSubdomains && host.endsWith(`.${this.hostname}`);
    if (!sameHost && !isSubdomain) {
      return { allowed: false, reason: `outside the approved target scope (${this.origin})` };
    }

    // Same host but a different port or scheme is still a different origin.
    if (sameHost && url.origin !== this.origin) {
      const httpsUpgrade = this.target.protocol === 'http:' && url.protocol === 'https:' && url.port === this.target.port;
      if (!httpsUpgrade) {
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
