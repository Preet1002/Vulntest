/**
 * Response body comparison helpers.
 *
 * The SQLi and path traversal modules decide almost everything by comparing a
 * probe response against a baseline, so the quality of these functions directly
 * controls the false-positive rate.
 */

const COMPARISON_LIMIT = 200_000;

/**
 * Remove the parts of a page that change on every request (timestamps, tokens,
 * nonces, request ids) so that two renders of the same page compare as equal.
 */
export function normalizeBody(body = '') {
  return String(body)
    .slice(0, COMPARISON_LIMIT)
    .replace(/<!--[\s\S]*?-->/g, ' ')
    .replace(/\b[0-9a-f]{16,}\b/gi, 'HEX')
    .replace(/\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b/gi, 'UUID')
    .replace(/\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}(:\d{2})?/g, 'TIMESTAMP')
    .replace(/\b\d{10,13}\b/g, 'EPOCH')
    .replace(/\d+/g, '0')
    .replace(/\s+/g, ' ')
    .trim()
    .toLowerCase();
}

const shingles = (text, size = 4) => {
  const set = new Set();
  for (let i = 0; i + size <= text.length; i += 1) {
    set.add(text.slice(i, i + size));
  }
  return set;
};

/**
 * Sørensen-Dice similarity over character shingles of the normalised bodies.
 * @returns {number} 0 (completely different) .. 1 (identical)
 */
export function similarity(a = '', b = '') {
  const left = normalizeBody(a);
  const right = normalizeBody(b);
  if (left === right) return 1;
  if (!left.length || !right.length) return 0;
  if (Math.abs(left.length - right.length) / Math.max(left.length, right.length) > 0.75) {
    return 0;
  }

  const leftSet = shingles(left);
  const rightSet = shingles(right);
  if (leftSet.size === 0 || rightSet.size === 0) return 0;

  let intersection = 0;
  const [small, large] = leftSet.size <= rightSet.size ? [leftSet, rightSet] : [rightSet, leftSet];
  for (const item of small) {
    if (large.has(item)) intersection += 1;
  }
  return (2 * intersection) / (leftSet.size + rightSet.size);
}

/** All indexes at which `needle` occurs in `haystack` (case-insensitive). */
export function findOccurrences(haystack = '', needle = '', limit = 10) {
  const positions = [];
  if (!needle) return positions;
  const source = String(haystack).toLowerCase();
  const term = needle.toLowerCase();
  let index = source.indexOf(term);
  while (index !== -1 && positions.length < limit) {
    positions.push(index);
    index = source.indexOf(term, index + term.length);
  }
  return positions;
}

/** A single-line snippet around `index`, safe to render in the dashboard. */
export function excerpt(body = '', index = 0, radius = 90) {
  const text = String(body);
  const start = Math.max(0, index - radius);
  const end = Math.min(text.length, index + radius);
  const prefix = start > 0 ? '...' : '';
  const suffix = end < text.length ? '...' : '';
  return `${prefix}${text.slice(start, end).replace(/\s+/g, ' ').trim()}${suffix}`;
}

/** Trim evidence to a sane size before it is stored or sent to the browser. */
export const clampEvidence = (value, maxLength = 600) => {
  const text = String(value ?? '');
  return text.length <= maxLength ? text : `${text.slice(0, maxLength)}…`;
};
