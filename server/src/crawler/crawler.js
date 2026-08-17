/**
 * Controlled breadth-first crawler.
 *
 * Bounded by: max pages, max depth, max requests, scan duration, robots.txt,
 * the same-origin policy and a per-endpoint variant cap that stops calendar and
 * pagination loops from consuming the whole page budget.
 */
import { parseHtml, extractEndpointsFromScript } from './parser.js';
import { runPassiveChecks } from '../scanner/passive.js';
import { HARD_LIMITS } from '../config/index.js';
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

const MAX_SCRIPT_FILES = 12;
const MAX_API_PROBES = 25;
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

  let pages = 0;
  let activeWorkers = 0;

  const enqueue = (rawUrl, depth) => {
    if (depth > ctx.config.maxDepth) return;
    const url = normalizeUrl(rawUrl);
    if (!url) return;
    if (!ctx.policy.isAllowed(url)) return;
    if (isSkippableAsset(url)) return;
    if (looksLikeCrawlTrap(url)) return;

    const key = dedupeKey(url);
    if (visited.has(key)) return;

    // Cap how many value-variants of the same path+parameter-set we visit.
    const signature = signatureKey(url);
    const seen = signatureCounts.get(signature) || 0;
    if (seen >= HARD_LIMITS.maxVariantsPerSignature) return;

    if (ctx.config.respectRobots && ctx.robots && !ctx.robots.isAllowed(url)) return;

    visited.add(key);
    signatureCounts.set(signature, seen + 1);
    queue.push({ url: url.href, depth });
  };

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
      if (ctx.policy.isAllowed(script) && scriptUrls.size < MAX_SCRIPT_FILES * 4) {
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
  return { pages };
}

/** Fetch a handful of same-origin scripts and mine them for API routes. */
async function analyzeScripts(ctx, scriptUrls, apiCandidates) {
  const list = [...scriptUrls].filter(isScriptAsset).slice(0, MAX_SCRIPT_FILES);
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
    .slice(0, MAX_API_PROBES);
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
