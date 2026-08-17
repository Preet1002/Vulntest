/**
 * Active scan orchestration.
 *
 * Turns the crawler's endpoint inventory into injection points and runs the
 * enabled detection modules against each one, reporting progress as it goes.
 */
import { buildInjectionPoints, describePoint } from './injectionPoints.js';
import { checkXss } from './xss.js';
import { checkSqli } from './sqli.js';
import { checkPathTraversal } from './pathTraversal.js';
import { pooled } from '../services/rateLimiter.js';
import { shortenUrl } from '../utils/url.js';

const CRAWL_PROGRESS_SHARE = 60;

/**
 * @param {import('../services/scanContext.js').ScanContext} ctx
 */
export async function runActiveScan(ctx) {
  const { points, skipped } = buildInjectionPoints(ctx);

  if (skipped.length > 0) {
    ctx.log(
      'info',
      `Skipped ${skipped.length} input(s) as unsafe or irrelevant to test: ${skipped.slice(0, 5).join('; ')}${skipped.length > 5 ? ' …' : ''}`,
    );
  }

  if (points.length === 0) {
    ctx.log('info', 'No testable parameters were discovered - reporting passive findings only.');
    ctx.setProgress(100);
    return { tested: 0 };
  }

  const enabled = Object.entries(ctx.config.checks)
    .filter(([name, on]) => on && name !== 'passive')
    .map(([name]) => name);
  ctx.log(
    'info',
    `Testing ${points.length} parameter(s) with: ${enabled.join(', ') || 'no active checks'}.`,
  );

  let completed = 0;

  await pooled(points, ctx.config.concurrency, async (point) => {
    if (ctx.shouldStop()) return;

    ctx.setProgress(
      CRAWL_PROGRESS_SHARE + (completed / points.length) * (100 - CRAWL_PROGRESS_SHARE),
      `${point.method} ${shortenUrl(point.displayUrl)} [${point.parameter}]`,
    );

    const checks = [
      ['xss', checkXss],
      ['sqli', checkSqli],
      ['pathTraversal', checkPathTraversal],
    ];

    for (const [name, check] of checks) {
      if (!ctx.config.checks[name] || ctx.shouldStop()) continue;
      try {
        await check(ctx, point);
      } catch (error) {
        ctx.log('error', `${name} check failed on ${describePoint(point)}: ${error.message}`);
      }
    }

    completed += 1;
    ctx.scan.statistics.parametersTested = completed;
  });

  ctx.setProgress(100);
  return { tested: completed };
}
