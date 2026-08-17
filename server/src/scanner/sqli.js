/**
 * Conservative SQL injection detection.
 *
 * Read-only, non-destructive checks only:
 *   1. Error-based - a single quote makes the application emit a database error
 *      that a benign control value does not produce.
 *   2. Boolean-based - a quote-balanced always-true condition renders the same
 *      page as the baseline while an always-false condition renders a
 *      measurably different one, and a benign control value changes nothing.
 *
 * There are no UNION queries, no stacked statements, no comment-truncation, no
 * time delays, and nothing that reads, writes or enumerates data. The scanner
 * reports that a parameter *appears* to reach a query unsafely; confirming and
 * exploiting it is a manual, authorised follow-up step.
 */
import { SEVERITY, CONFIDENCE } from '../config/index.js';
import { similarity, excerpt } from '../utils/text.js';
import { DATABASE_ERRORS, matchSignatures } from './signatures.js';
import { sendProbe } from './injectionPoints.js';

const RECOMMENDATION =
  'Use parameterized queries / prepared statements so user input is never concatenated into SQL. ' +
  'Where an identifier (table, column, sort direction) must be dynamic, validate it against an allowlist. ' +
  'Apply least-privilege database accounts, and return generic error pages so query errors are not exposed to clients.';

/** Similarity below this means "meaningfully different page". */
const DIFFERENCE_MARGIN = 0.2;
/** Similarity within this of the baseline means "same page". */
const SAME_MARGIN = 0.05;

const isNumeric = (value) => /^\d{1,12}$/.test(String(value).trim());

/**
 * @param {import('../services/scanContext.js').ScanContext} ctx
 * @param {object} point
 */
export async function checkSqli(ctx, point) {
  const base = point.baseValue && String(point.baseValue).trim() !== '' ? String(point.baseValue) : '1';

  // --- baseline, measured twice to establish how noisy the page is ---------
  const baseline = await sendProbe(ctx, point, base, 'sqli-baseline');
  if (!baseline.ok || !baseline.body) return;
  if (baseline.status >= 500) return; // already broken - comparisons are meaningless

  const baselineRepeat = await sendProbe(ctx, point, base, 'sqli-baseline');
  if (!baselineRepeat.ok) return;
  const noiseFloor = similarity(baseline.body, baselineRepeat.body);
  // Highly dynamic pages (ads, tokens, timestamps everywhere) cannot be
  // compared reliably, so behavioural checks are skipped for them.
  const comparable = noiseFloor >= 0.9;

  // --- 1. error based -------------------------------------------------------
  const baselineError = matchSignatures(baseline.body, DATABASE_ERRORS);
  const quoted = await sendProbe(ctx, point, `${base}'`, 'sqli-error');
  if (!quoted.ok) return;

  const quotedError = matchSignatures(quoted.body, DATABASE_ERRORS);
  if (quotedError.matched && !baselineError.matched) {
    // A doubled quote is syntactically balanced. If that clears the error, the
    // value is very clearly being concatenated into the statement.
    const balanced = await sendProbe(ctx, point, `${base}''`, 'sqli-balanced');
    const balancedError = matchSignatures(balanced.body || '', DATABASE_ERRORS);
    const balancedClean = balanced.ok && !balancedError.matched;

    ctx.addFinding({
      type: 'Potential SQL Injection',
      severity: SEVERITY.HIGH,
      confidence: balancedClean ? CONFIDENCE.HIGH : CONFIDENCE.MEDIUM,
      url: quoted.url,
      parameter: point.parameter,
      method: point.method,
      description:
        `Appending a single quote to "${point.parameter}" caused the application to return a ` +
        `${quotedError.label || 'database'} error, which the unmodified request did not produce. ` +
        (balancedClean
          ? 'Sending a balanced pair of quotes cleared the error again, which is the classic signature of a value ' +
            'being concatenated directly into a SQL statement. '
          : 'The balanced-quote control still errored, so the parser state is less certain. ') +
        'No data was read, modified or extracted by this check.',
      evidence:
        `Baseline value: ${base} -> HTTP ${baseline.status}, no database error\n` +
        `Probe value: ${base}' -> HTTP ${quoted.status}, matched ${quotedError.label || 'SQL'} error signature\n` +
        `Balanced probe: ${base}'' -> ${balanced.ok ? `HTTP ${balanced.status}, ${balancedClean ? 'no error' : 'error still present'}` : 'request failed'}\n` +
        `Error text: ${quotedError.match}`,
      recommendation: RECOMMENDATION,
      references: ['https://owasp.org/www-community/attacks/SQL_Injection', 'CWE-89'],
    });
    return;
  }

  if (!comparable) return;

  // --- control: does *any* modified value change the page? ------------------
  const control = await sendProbe(ctx, point, `${base}zqx9`, 'sqli-control');
  if (!control.ok) return;
  const controlSimilarity = similarity(baseline.body, control.body);
  const controlChangesPage =
    controlSimilarity < noiseFloor - DIFFERENCE_MARGIN || control.status !== baseline.status;

  // --- 2. server error triggered only by the quote --------------------------
  if (quoted.status >= 500 && baseline.status < 500 && control.status < 500) {
    ctx.addFinding({
      type: 'Potential SQL Injection',
      severity: SEVERITY.MEDIUM,
      confidence: CONFIDENCE.LOW,
      url: quoted.url,
      parameter: point.parameter,
      method: point.method,
      description:
        `A single quote in "${point.parameter}" produced HTTP ${quoted.status} while both the original value and a ` +
        `benign control value (${base}zqx9) returned HTTP ${baseline.status}. No database error message was exposed, ` +
        `so this is an unhandled-error indicator rather than proof of injection - a quote-sensitive parameter often ` +
        `means unescaped string concatenation, but it can also be strict input validation failing loudly. ` +
        `Verify manually before treating it as exploitable.`,
      evidence:
        `Original value: ${base} -> HTTP ${baseline.status}\n` +
        `Control value: ${base}zqx9 -> HTTP ${control.status}\n` +
        `Quote probe: ${base}' -> HTTP ${quoted.status}`,
      recommendation: RECOMMENDATION,
      references: ['CWE-89'],
    });
    return;
  }

  if (controlChangesPage) return; // the endpoint reacts to any value - no signal

  // --- 3. boolean based -----------------------------------------------------
  const variants = isNumeric(base)
    ? [
        { label: 'numeric', truthy: `${base} AND 1=1`, falsy: `${base} AND 1=2` },
        { label: 'string', truthy: `${base}' AND '1'='1`, falsy: `${base}' AND '1'='2` },
      ]
    : [{ label: 'string', truthy: `${base}' AND '1'='1`, falsy: `${base}' AND '1'='2` }];

  for (const variant of variants) {
    if (ctx.shouldStop()) return;

    const truthy = await sendProbe(ctx, point, variant.truthy, 'sqli-boolean');
    if (!truthy.ok || !truthy.body) continue;
    const falsy = await sendProbe(ctx, point, variant.falsy, 'sqli-boolean');
    if (!falsy.ok || !falsy.body) continue;

    const truthySimilarity = similarity(baseline.body, truthy.body);
    const falsySimilarity = similarity(baseline.body, falsy.body);
    const pairSimilarity = similarity(truthy.body, falsy.body);

    const truthyMatchesBaseline = truthySimilarity >= noiseFloor - SAME_MARGIN;
    const falsyDiffers = falsySimilarity < noiseFloor - DIFFERENCE_MARGIN;
    const pairDiffers = pairSimilarity < noiseFloor - DIFFERENCE_MARGIN;

    if (truthyMatchesBaseline && falsyDiffers && pairDiffers) {
      ctx.addFinding({
        type: 'Potential SQL Injection',
        severity: SEVERITY.HIGH,
        confidence: CONFIDENCE.MEDIUM,
        url: truthy.url,
        parameter: point.parameter,
        method: point.method,
        description:
          `"${point.parameter}" responds to boolean logic in a way that suggests the value reaches a SQL query ` +
          `unsafely. An always-true condition (${variant.truthy}) returned the same page as the original request, ` +
          `while an always-false condition (${variant.falsy}) returned a different page. A benign control value ` +
          `changed nothing, which rules out simple value sensitivity. The conditions are read-only - no data was ` +
          `selected, modified or extracted.`,
        evidence:
          `Baseline stability: ${noiseFloor.toFixed(3)} (two identical requests)\n` +
          `Control (${base}zqx9) similarity to baseline: ${controlSimilarity.toFixed(3)}\n` +
          `TRUE  (${variant.truthy}) similarity to baseline: ${truthySimilarity.toFixed(3)} [HTTP ${truthy.status}]\n` +
          `FALSE (${variant.falsy}) similarity to baseline: ${falsySimilarity.toFixed(3)} [HTTP ${falsy.status}]\n` +
          `TRUE vs FALSE similarity: ${pairSimilarity.toFixed(3)}`,
        recommendation: RECOMMENDATION,
        references: ['https://owasp.org/www-community/attacks/Blind_SQL_Injection', 'CWE-89'],
      });
      return;
    }
  }
}

/** Passive helper: a database error visible during normal crawling. */
export function reportDatabaseErrorInBody(ctx, response) {
  const match = matchSignatures(response.body, DATABASE_ERRORS);
  if (!match.matched) return;

  const index = response.body.indexOf(match.match);
  let origin = response.url;
  try {
    origin = new URL(response.url).origin;
  } catch {
    /* keep the raw URL as the dedupe scope */
  }
  ctx.addFinding({
    type: 'Database Error Disclosure',
    severity: SEVERITY.MEDIUM,
    confidence: CONFIDENCE.HIGH,
    url: response.url,
    parameter: null,
    method: response.method,
    dedupeKey: `db-error|${match.label}|${origin}`,
    description:
      `The page exposes a raw ${match.label || 'database'} error message. Query errors reaching the client reveal ` +
      `the database engine, schema fragments and query structure, all of which make other injection attacks easier ` +
      `and often indicate missing error handling around query execution.`,
    evidence: index >= 0 ? excerpt(response.body, index, 140) : match.match,
    recommendation:
      'Return a generic error page to clients and log the detail server-side. Disable framework debug mode in ' +
      'production and make sure database exceptions are caught at the data-access layer.',
    references: ['CWE-209'],
  });
}
