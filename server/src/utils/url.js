/**
 * URL normalisation helpers.
 *
 * Two different keys are produced for every URL:
 *   - `normalizeUrl()`   the URL actually requested (kept faithful).
 *   - `dedupeKey()`      the identity used by the visited set. Tracking noise is
 *                        stripped here so that ?utm_source=x does not create a
 *                        second copy of every page.
 *   - `signatureKey()`   path + parameter *names*. Used to cap how many value
 *                        variants of the same endpoint get crawled, which is
 *                        what stops calendars and infinite pagination.
 */

/** Query parameters that never change the resource, only the analytics trail. */
const TRACKING_PARAMS = [
  /^utm_/i,
  /^ga_/i,
  /^_ga$/i,
  /^_gl$/i,
  /^gclid$/i,
  /^dclid$/i,
  /^fbclid$/i,
  /^msclkid$/i,
  /^mc_(cid|eid)$/i,
  /^igshid$/i,
  /^ref_?(src|url)?$/i,
  /^referrer$/i,
  /^source$/i,
  /^campaign$/i,
  /^yclid$/i,
  /^_hs(enc|mi)$/i,
];

/** Non-document extensions that are pointless to crawl as pages. */
const SKIPPED_EXTENSIONS = new Set([
  'png', 'jpg', 'jpeg', 'gif', 'webp', 'avif', 'svg', 'ico', 'bmp', 'tiff',
  'woff', 'woff2', 'ttf', 'otf', 'eot',
  'mp3', 'mp4', 'avi', 'mov', 'wmv', 'flv', 'webm', 'ogg', 'wav', 'm4a',
  'zip', 'tar', 'gz', 'bz2', '7z', 'rar', 'dmg', 'iso', 'exe', 'msi', 'apk',
  'pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx', 'psd', 'ai',
  'css', 'map',
]);

const NON_FETCHABLE_SCHEMES = /^(mailto|tel|sms|javascript|data|blob|about|file|ftp|ws|wss):/i;

export function getExtension(pathname) {
  const lastSegment = pathname.split('/').pop() || '';
  const dot = lastSegment.lastIndexOf('.');
  if (dot <= 0) return '';
  return lastSegment.slice(dot + 1).toLowerCase();
}

export const isSkippableAsset = (url) => SKIPPED_EXTENSIONS.has(getExtension(safePathname(url)));

export const isScriptAsset = (url) => ['js', 'mjs', 'cjs', 'jsx', 'ts'].includes(getExtension(safePathname(url)));

function safePathname(url) {
  try {
    return (url instanceof URL ? url : new URL(url)).pathname;
  } catch {
    return String(url);
  }
}

/**
 * Resolve `href` against `base` and clean it up for requesting.
 * @returns {URL|null} null when the link is not a fetchable http(s) URL.
 */
export function normalizeUrl(href, base) {
  if (typeof href !== 'string') return null;
  const raw = href.trim();
  if (!raw || raw.startsWith('#') || NON_FETCHABLE_SCHEMES.test(raw)) return null;

  let url;
  try {
    url = base ? new URL(raw, base) : new URL(raw);
  } catch {
    return null;
  }
  if (url.protocol !== 'http:' && url.protocol !== 'https:') return null;

  url.hash = '';
  url.hostname = url.hostname.toLowerCase();
  if (
    (url.protocol === 'http:' && url.port === '80') ||
    (url.protocol === 'https:' && url.port === '443')
  ) {
    url.port = '';
  }
  // Collapse duplicate slashes in the path but keep a trailing slash intact.
  url.pathname = url.pathname.replace(/\/{2,}/g, '/');
  return url;
}

/** Stable identity for the visited set: tracking params dropped, params sorted. */
export function dedupeKey(input) {
  const url = input instanceof URL ? new URL(input.href) : normalizeUrl(input);
  if (!url) return String(input);

  const params = [...url.searchParams.entries()]
    .filter(([name]) => !TRACKING_PARAMS.some((pattern) => pattern.test(name)))
    .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));

  const search = params.length
    ? `?${params.map(([name, value]) => `${name}=${value}`).join('&')}`
    : '';
  const path = url.pathname.replace(/\/+$/, '') || '/';
  return `${url.protocol}//${url.host}${path}${search}`;
}

/** Identity ignoring parameter *values* - used to cap per-endpoint variants. */
export function signatureKey(input) {
  const url = input instanceof URL ? input : normalizeUrl(input);
  if (!url) return String(input);
  const names = [...url.searchParams.keys()]
    .filter((name) => !TRACKING_PARAMS.some((pattern) => pattern.test(name)))
    .sort()
    .join(',');
  const path = url.pathname.replace(/\/+$/, '') || '/';
  return `${url.host}${path}?${names}`;
}

export const getQueryParameters = (input) => {
  const url = input instanceof URL ? input : normalizeUrl(input);
  if (!url) return [];
  return [...new Set(url.searchParams.keys())];
};

/** Replace one query parameter, leaving everything else untouched. */
export function withParameter(input, name, value) {
  const url = new URL(input instanceof URL ? input.href : input);
  url.searchParams.set(name, value);
  return url;
}

/**
 * Guard against crawler traps: very deep paths and paths that repeat the same
 * segment over and over (typical of relative-link loops).
 */
export function looksLikeCrawlTrap(input) {
  const url = input instanceof URL ? input : normalizeUrl(input);
  if (!url) return true;
  const segments = url.pathname.split('/').filter(Boolean);
  if (segments.length > 12) return true;

  const counts = new Map();
  for (const segment of segments) {
    const seen = (counts.get(segment) || 0) + 1;
    if (seen >= 3) return true;
    counts.set(segment, seen);
  }
  return false;
}

export const pathDepth = (input) => {
  const url = input instanceof URL ? input : normalizeUrl(input);
  if (!url) return 0;
  return url.pathname.split('/').filter(Boolean).length;
};

/** Short display form used in the activity log and the dashboard. */
export function shortenUrl(input, maxLength = 70) {
  const text = input instanceof URL ? input.href : String(input);
  if (text.length <= maxLength) return text;
  return `${text.slice(0, maxLength - 3)}...`;
}
