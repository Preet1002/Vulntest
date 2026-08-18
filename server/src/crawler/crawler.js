/**
 * Controlled breadth-first crawler.
 *
 * Discovery comes from three places: the site's sitemaps, links in the HTML and
 * endpoint-looking strings in its JavaScript.
 *
 * Bounded by: max pages, max depth, max requests, scan duration, robots.txt,
 * the same-site policy and a per-endpoint variant cap that stops calendar and
 * pagination loops from consuming the whole page budget. Whenever one of those
 * bounds is what ended the crawl, it is written to the activity log.
 */
import { parseHtml, extractEndpointsFromScript } from './parser.js';
import { runPassiveChecks } from '../scanner/passive.js';
import { HARD_LIMITS } from '../config/index.js';
import { collectSitemapUrls } from '../services/sitemap.js';
import {
  dedupeKey,
  signatureKey,
  normalizeUrl,
  getQueryParameters,
  isSkippableAsset,
  isScriptAsset,
  looksLikeCrawlTrap,
  shortenUrl,
} from '../utils/url.js';

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

/** Endpoints whose name suggests a GET would change state - never probed. */
const STATE_CHANGING = /(logout|signout|sign-out|delete|remove|destroy|reset|purge|drop|revoke|deactivate|unsubscribe|cancel)/i;

/**
 * @param {import('../services/scanContext.js').ScanContext} ctx
 * @returns {Promise<{pages: number}>}
 */
export async function crawl(ctx) {
  const startUrl = new URL(ctx.scan.target);
  const queue = [{ url: startUrl.href, depth: 0 }];
  const visited = new Set([dedupeKey(startUrl)]);
  const signatureCounts = new Map([[signatureKey(startUrl), 1]]);
  const scriptUrls = new Set();
  const apiCandidates = new Set();

  // Why links were rejected. Reported at the end so a thin crawl is explained
  // rather than silently looking like "the site only has three pages".
  const skipped = {
    offScope: 0,
    robots: 0,
    depth: 0,
    variantCap: 0,
    trap: 0,
    asset: 0,
  };

  let pages = 0;
  let activeWorkers = 0;
  let queueOverflow = 0;

  /**
   * @param {string|URL} rawUrl
   * @param {number} depth
   * @param {{trusted?: boolean}} [options] `trusted` URLs come from a sitemap -
   *   the site published them itself, so the anti-trap variant cap is not
   *   applied to them.
   */
  const enqueue = (rawUrl, depth, { trusted = false } = {}) => {
    if (depth > ctx.config.maxDepth) {
      skipped.depth += 1;
      return;
    }
    const url = normalizeUrl(rawUrl);
    if (!url) return;
    if (!ctx.policy.isAllowed(url)) {
      skipped.offScope += 1;
      return;
    }
    if (isSkippableAsset(url)) {
      skipped.asset += 1;
      return;
    }
    if (!trusted && looksLikeCrawlTrap(url)) {
      skipped.trap += 1;
      return;
    }

    const key = dedupeKey(url);
    if (visited.has(key)) return;

    // Cap how many value-variants of the same path+parameter-set we visit.
    const signature = signatureKey(url);
    const seen = signatureCounts.get(signature) || 0;
    if (!trusted && seen >= ctx.config.maxVariantsPerSignature) {
      skipped.variantCap += 1;
      return;
    }

    if (ctx.config.respectRobots && ctx.robots && !ctx.robots.isAllowed(url)) {
      skipped.robots += 1;
      return;
    }

    // The queue is bounded so a very large site cannot grow it without limit;
    // anything past the ceiling is simply not scheduled.
    if (queue.length >= HARD_LIMITS.maxPages * 4) {
      queueOverflow += 1;
      return;
    }

    visited.add(key);
    signatureCounts.set(signature, seen + 1);
    queue.push({ url: url.href, depth });
  };

  // --- seed the queue from the site's own sitemaps -------------------------
  if (ctx.config.useSitemap && !ctx.shouldStop()) {
    ctx.setPhase('sitemap', 'Looking for sitemaps to seed the crawl.');
    try {
      const { urls } = await collectSitemapUrls(ctx, ctx.robots?.sitemaps || []);
      let seeded = 0;
      for (const url of urls) {
        const before = queue.length;
        enqueue(url, 0, { trusted: true });
        if (queue.length > before) seeded += 1;
      }
      if (seeded > 0) {
        ctx.log('info', `Seeded ${seeded} URL(s) from sitemaps (${urls.length} listed).`);
      }
    } catch (error) {
      ctx.log('warn', `Sitemap discovery failed: ${error.message}`);
    }
    ctx.setPhase('crawling');
  }

  const processPage = async (item) => {
    const response = await ctx.http.get(item.url, { purpose: 'crawl' });
    pages += 1;
    ctx.scan.statistics.pages = pages;

    const endpoint = ctx.addEndpoint({
      url: response.url || item.url,
      method: 'GET',
      source: item.depth === 0 ? 'seed' : 'link',
      parameters: getQueryParameters(item.url),
      statusCode: response.status,
      contentType: response.contentType,
      depth: item.depth,
    });

    if (!response.ok) {
      ctx.log('warn', `Request failed: ${shortenUrl(item.url)} - ${response.error}`);
      return;
    }

    // A redirect out of scope returns a valid but empty response. Saying so is
    // what turns "the crawl found nothing" into something the operator can act
    // on (usually by allowing subdomains).
    if (response.blockedRedirect) {
      ctx.log(
        'warn',
        `${shortenUrl(item.url)} redirects to ${shortenUrl(response.blockedRedirect)}, which is out of scope - not crawled.`,
      );
      return;
    }

    const isHtml = /html|xhtml/i.test(response.contentType) || /^\s*<(!doctype|html)/i.test(response.body);
    if (!isHtml) {
      if (ctx.config.checks.passive) runPassiveChecks(ctx, response, null);
      return;
    }

    const parsed = parseHtml(response.body, response.url || item.url);
    if (parsed.title) endpoint.title = parsed.title;

    if (ctx.config.checks.passive) runPassiveChecks(ctx, response, parsed);

    for (const link of parsed.links) enqueue(link, item.depth + 1);

    for (const script of parsed.scripts) {
      if (ctx.policy.isAllowed(script) && scriptUrls.size < HARD_LIMITS.maxScriptFiles * 4) {
        scriptUrls.add(script);
      }
    }
    for (const candidate of parsed.apiCandidates) {
      if (ctx.policy.isAllowed(candidate)) apiCandidates.add(candidate);
    }

    for (const form of parsed.forms) {
      if (!ctx.policy.isAllowed(form.action)) continue;
      ctx.addEndpoint({
        url: form.action,
        method: form.method,
        source: 'form',
        parameters: form.inputs.map((input) => input.name),
        forms: [{ ...form, foundOn: response.url || item.url }],
        depth: item.depth,
      });
      // A GET form's action is also a normal page worth crawling.
      if (form.method === 'GET') enqueue(form.action, item.depth + 1);
    }
  };

  const worker = async () => {
    for (;;) {
      if (ctx.shouldStop() || pages >= ctx.config.maxPages) return;

      const item = queue.shift();
      if (!item) {
        // Another worker may still be about to enqueue more links.
        if (activeWorkers === 0) return;
        await sleep(50);
        continue;
      }

      activeWorkers += 1;
      try {
        ctx.setProgress(
          Math.min(55, (pages / ctx.config.maxPages) * 55),
          item.url,
        );
        await processPage(item);
      } catch (error) {
        ctx.log('error', `Crawl error on ${shortenUrl(item.url)}: ${error.message}`);
      } finally {
        activeWorkers -= 1;
      }
    }
  };

  await Promise.all(
    new Array(ctx.config.concurrency).fill(null).map(() => worker()),
  );

  if (!ctx.shouldStop()) {
    await analyzeScripts(ctx, scriptUrls, apiCandidates);
    await probeApiCandidates(ctx, apiCandidates);
  }

  ctx.log(
    'info',
    `Crawl finished: ${pages} page(s), ${ctx.endpoints.length} endpoint(s), ${ctx.http.requestCount} request(s).`,
  );
  reportCrawlLimits(ctx, { pages, queued: queue.length, skipped, queueOverflow });
  return { pages };
}

/**
 * Explain what ended the crawl and what was left on the table. Without this a
 * short scan is indistinguishable from a small site, which is the single most
 * confusing thing a crawler can do.
 */
function reportCrawlLimits(ctx, { pages, queued, skipped, queueOverflow }) {
  if (pages >= ctx.config.maxPages) {
    ctx.log(
      'warn',
      `Page limit reached (${ctx.config.maxPages}); ${queued} known URL(s) were left uncrawled. Raise "Maximum pages" to go further.`,
    );
  } else if (ctx.http.budgetExhausted) {
    ctx.log(
      'warn',
      `Request budget reached (${ctx.config.maxRequests}); ${queued} known URL(s) were left uncrawled.`,
    );
  }

  const reasons = [];
  if (skipped.robots > 0) reasons.push(`${skipped.robots} disallowed by robots.txt`);
  if (skipped.offScope > 0) reasons.push(`${skipped.offScope} outside the target scope`);
  if (skipped.depth > 0) reasons.push(`${skipped.depth} beyond depth ${ctx.config.maxDepth}`);
  if (skipped.variantCap > 0) {
    reasons.push(`${skipped.variantCap} over the ${ctx.config.maxVariantsPerSignature}-variant per-endpoint cap`);
  }
  if (skipped.trap > 0) reasons.push(`${skipped.trap} look like crawl traps`);
  if (queueOverflow > 0) reasons.push(`${queueOverflow} past the queue ceiling`);

  if (reasons.length > 0) {
    ctx.log('info', `Links not followed: ${reasons.join(', ')}.`);
  }

  if (pages <= 1 && skipped.offScope > 0) {
    ctx.log(
      'warn',
      'Almost every link pointed off-scope. If the site spreads across subdomains, enable "Allow subdomains" and scan again.',
    );
  }
}

/** Fetch a handful of same-origin scripts and mine them for API routes. */
async function analyzeScripts(ctx, scriptUrls, apiCandidates) {
  const list = [...scriptUrls].filter(isScriptAsset).slice(0, HARD_LIMITS.maxScriptFiles);
  if (list.length === 0) return;

  ctx.setPhase('analyzing-scripts', `Analyzing ${list.length} script file(s) for endpoints.`);
  for (const scriptUrl of list) {
    if (ctx.shouldStop()) return;
    const response = await ctx.http.get(scriptUrl, { purpose: 'script' });
    if (!response.ok || !response.body) continue;
    for (const candidate of extractEndpointsFromScript(response.body, response.url || scriptUrl)) {
      if (ctx.policy.isAllowed(candidate)) apiCandidates.add(candidate);
    }
  }
}

/**
 * Confirm which script-derived candidates actually exist. Anything that looks
 * state-changing is inventoried without being requested.
 */
async function probeApiCandidates(ctx, apiCandidates) {
  const known = new Set(ctx.endpoints.map((endpoint) => dedupeKey(endpoint.url)));
  const list = [...apiCandidates]
    .filter((url) => !known.has(dedupeKey(url)))
    .slice(0, HARD_LIMITS.maxApiProbes);
  if (list.length === 0) return;

  ctx.setPhase('probing-endpoints', `Verifying ${list.length} endpoint(s) discovered in JavaScript.`);
  for (const candidate of list) {
    if (ctx.shouldStop()) return;

    if (STATE_CHANGING.test(candidate)) {
      ctx.addEndpoint({
        url: candidate,
        method: 'GET',
        source: 'script (not requested)',
        parameters: getQueryParameters(candidate),
      });
      continue;
    }

    const response = await ctx.http.get(candidate, { purpose: 'endpoint-probe' });
    ctx.addEndpoint({
      url: response.url || candidate,
      method: 'GET',
      source: 'script',
      parameters: getQueryParameters(candidate),
      statusCode: response.status,
      contentType: response.contentType,
    });
  }
}
