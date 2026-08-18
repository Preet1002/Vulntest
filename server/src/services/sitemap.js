/**
 * Sitemap discovery.
 *
 * Following links from the start page only reaches whatever the front page
 * happens to link to, which on a real site is a small fraction of it. Almost
 * every public site publishes the rest of its URLs in a sitemap, so reading
 * those is the difference between crawling a handful of pages and covering the
 * site. Sitemaps are advisory input only: every URL that comes out of one is
 * still put through the scope policy, robots.txt and the crawl budgets.
 */
import { HARD_LIMITS } from '../config/index.js';
import { normalizeUrl, shortenUrl } from '../utils/url.js';

/** Conventional locations to try when robots.txt does not name a sitemap. */
const WELL_KNOWN_PATHS = [
  '/sitemap.xml',
  '/sitemap_index.xml',
  '/sitemap-index.xml',
  '/wp-sitemap.xml',
  '/sitemap/sitemap.xml',
];

const LOC_PATTERN = /<loc>\s*([^<\s][^<]*?)\s*<\/loc>/gi;
const IS_SITEMAP_INDEX = /<sitemapindex[\s>]/i;

/**
 * Pull URLs out of a sitemap document. Handles both XML sitemaps and the
 * plain-text form (one URL per line), which some sites serve instead.
 * @returns {string[]}
 */
export function parseSitemap(body) {
  const urls = [];

  LOC_PATTERN.lastIndex = 0;
  let match = LOC_PATTERN.exec(body);
  while (match !== null) {
    urls.push(decodeEntities(match[1]));
    match = LOC_PATTERN.exec(body);
  }

  // Plain-text sitemap: no <loc> elements, just one absolute URL per line.
  if (urls.length === 0 && !/^\s*</.test(body)) {
    for (const line of body.split(/\r?\n/)) {
      const trimmed = line.trim();
      if (/^https?:\/\//i.test(trimmed)) urls.push(trimmed);
    }
  }

  return urls;
}

const decodeEntities = (value) =>
  value
    .replace(/&amp;/g, '&')
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"')
    .replace(/&#39;/g, "'");

/**
 * Fetch the sitemaps for a target and return every in-scope page URL they list.
 *
 * Sitemap indexes are followed one level at a time up to
 * `HARD_LIMITS.maxSitemapDocuments` documents, so a site that indexes thousands
 * of sitemaps cannot turn discovery into the whole scan.
 *
 * @param {import('./scanContext.js').ScanContext} ctx
 * @param {string[]} [hintedUrls] sitemap URLs named by robots.txt
 * @returns {Promise<string[]>} absolute, in-scope, de-duplicated URLs
 */
export async function collectSitemapUrls(ctx, hintedUrls = []) {
  const origin = ctx.policy.origin;
  const queue = [];
  const queued = new Set();

  const pushDocument = (rawUrl) => {
    const url = normalizeUrl(rawUrl);
    if (!url || !ctx.policy.isAllowed(url)) return;
    if (queued.has(url.href)) return;
    queued.add(url.href);
    queue.push(url.href);
  };

  for (const hint of hintedUrls) pushDocument(hint);
  for (const path of WELL_KNOWN_PATHS) pushDocument(`${origin}${path}`);

  const found = new Set();
  let documentsRead = 0;

  while (queue.length > 0 && documentsRead < HARD_LIMITS.maxSitemapDocuments) {
    if (ctx.shouldStop() || found.size >= HARD_LIMITS.maxSitemapUrls) break;

    const documentUrl = queue.shift();
    // Gzipped sitemaps would need to be inflated before parsing; the plain
    // sibling almost always exists, so they are skipped rather than mis-parsed.
    if (documentUrl.endsWith('.gz')) continue;

    // eslint-disable-next-line no-await-in-loop
    const response = await ctx.http.get(documentUrl, { purpose: 'sitemap' });
    documentsRead += 1;
    if (!response.ok || response.status !== 200 || !response.body) continue;
    if (response.contentType && !/xml|text\/plain|text\//i.test(response.contentType)) continue;

    const entries = parseSitemap(response.body);
    if (entries.length === 0) continue;

    if (IS_SITEMAP_INDEX.test(response.body)) {
      for (const entry of entries) pushDocument(entry);
      ctx.log('info', `Sitemap index ${shortenUrl(documentUrl)} lists ${entries.length} sitemap(s).`);
      continue;
    }

    let added = 0;
    for (const entry of entries) {
      if (found.size >= HARD_LIMITS.maxSitemapUrls) break;
      const url = normalizeUrl(entry);
      if (!url || !ctx.policy.isAllowed(url)) continue;
      if (found.has(url.href)) continue;
      found.add(url.href);
      added += 1;
    }
    if (added > 0) {
      ctx.log('info', `Sitemap ${shortenUrl(documentUrl)} contributed ${added} URL(s).`);
    }
  }

  if (found.size === 0 && documentsRead > 0) {
    ctx.log('info', 'No usable sitemap found - relying on link discovery alone.');
  }

  return { urls: [...found], documentsRead };
}
