/**
 * Reflected XSS detection - reflection analysis only.
 *
 * The scanner never sends a payload designed to execute script. It sends a
 * random canary, checks whether the canary comes back, and then sends the same
 * canary followed by the four markup-significant characters `"'<>`. Whether
 * those characters survive unencoded - and in which HTML context they land -
 * is the entire basis for the finding.
 *
 * Evidence tiers reported:
 *   High confidence   dangerous characters survive in a context where they
 *                     break out of the surrounding syntax
 *   Medium confidence dangerous characters survive, breakout less certain
 *   Low  confidence   the value is reflected but correctly encoded (reported
 *                     as informational, never as XSS)
 */
import { SEVERITY, CONFIDENCE } from '../config/index.js';
import { canaryToken } from '../utils/ids.js';
import { findOccurrences, excerpt } from '../utils/text.js';
import { sendProbe } from './injectionPoints.js';

/** Markup-significant characters. Harmless on their own - no script, no event handler. */
const PROBE_CHARS = ['"', "'", '<', '>'];
const PROBE_SUFFIX = PROBE_CHARS.join('');

const RECOMMENDATION =
  'Apply context-aware output encoding when rendering user input: HTML-entity encode for element text, ' +
  'attribute-encode (and always quote) for attribute values, and JavaScript-string encode for values placed ' +
  'inside scripts. Prefer a templating engine that escapes by default, avoid innerHTML with untrusted data, ' +
  'and add a Content-Security-Policy that disallows inline script as defence in depth.';

/** Byte ranges occupied by <script>/<style> blocks and HTML comments. */
function specialRegions(body) {
  const regions = [];
  const collect = (pattern, kind) => {
    pattern.lastIndex = 0;
    let match = pattern.exec(body);
    while (match !== null) {
      regions.push({ kind, start: match.index, end: match.index + match[0].length });
      match = pattern.exec(body);
    }
  };
  collect(/<script\b[^>]*>[\s\S]*?(?:<\/script\s*>|$)/gi, 'javascript');
  collect(/<style\b[^>]*>[\s\S]*?(?:<\/style\s*>|$)/gi, 'css');
  collect(/<!--[\s\S]*?(?:-->|$)/g, 'comment');
  return regions;
}

/**
 * Work out where in the document the reflection landed.
 * @returns {{context: string, detail: string, quote: string|null, attribute: string|null}}
 */
export function determineContext(body, index, regions = specialRegions(body)) {
  for (const region of regions) {
    if (index > region.start && index < region.end) {
      if (region.kind === 'javascript') {
        const prefix = body.slice(region.start, index);
        const quote = openStringQuote(prefix);
        return {
          context: 'JavaScript',
          detail: quote
            ? `inside a ${quote === '"' ? 'double' : 'single'}-quoted JavaScript string literal`
            : 'inside a <script> block, outside a string literal',
          quote,
          attribute: null,
        };
      }
      if (region.kind === 'css') {
        return { context: 'CSS', detail: 'inside a <style> block', quote: null, attribute: null };
      }
      return { context: 'HTML comment', detail: 'inside an HTML comment', quote: null, attribute: null };
    }
  }

  const lastOpen = body.lastIndexOf('<', index);
  const lastClose = body.lastIndexOf('>', index);
  if (lastOpen > lastClose) {
    // Inside a tag, so the value is part of an attribute.
    const tagSource = body.slice(lastOpen, index);
    // Find the attribute whose value is still open at this position. Each
    // alternative anchors at the end of the prefix, so a double-quoted value
    // containing apostrophes (onclick="f('x')") resolves correctly.
    const doubleQuoted = tagSource.match(/([\w:.-]+)\s*=\s*"([^"]*)$/);
    const singleQuoted = doubleQuoted ? null : tagSource.match(/([\w:.-]+)\s*=\s*'([^']*)$/);
    const unquoted = doubleQuoted || singleQuoted ? null : tagSource.match(/([\w:.-]+)\s*=\s*([^\s"'>]*)$/);
    const attributeMatch = doubleQuoted || singleQuoted || unquoted;

    const attribute = attributeMatch ? attributeMatch[1].toLowerCase() : null;
    const quote = doubleQuoted ? '"' : singleQuoted ? "'" : null;
    const isUrlAttribute = attribute && /^(href|src|action|formaction|data|poster|cite|srcset)$/.test(attribute);
    const isEventAttribute = attribute && /^on[a-z]+$/.test(attribute);

    return {
      context: isEventAttribute ? 'Event handler attribute' : isUrlAttribute ? 'URL attribute' : 'HTML attribute',
      detail: attribute
        ? `in the ${quote ? `${quote === '"' ? 'double' : 'single'}-quoted` : 'unquoted'} "${attribute}" attribute`
        : 'inside a tag',
      quote,
      attribute,
    };
  }

  return { context: 'HTML text', detail: 'in HTML element text', quote: null, attribute: null };
}

/** Is position `index` inside an unterminated JS string literal? */
function openStringQuote(prefix) {
  let quote = null;
  for (let i = 0; i < prefix.length; i += 1) {
    const char = prefix[i];
    if (char === '\\') {
      i += 1;
      continue;
    }
    if (quote) {
      if (char === quote) quote = null;
    } else if (char === '"' || char === "'" || char === '`') {
      quote = char;
    }
  }
  return quote;
}

/** Which of the probe characters came back unencoded next to the canary? */
function survivingCharacters(body, index, token) {
  const tail = body.slice(index + token.length, index + token.length + 40);
  return PROBE_CHARS.filter((char) => tail.includes(char));
}

/**
 * Score one reflection.
 * @returns {{severity: string, confidence: string, rationale: string}|null}
 */
function assess(context, surviving) {
  const has = (char) => surviving.includes(char);
  const tagBreakout = has('<') && has('>');

  if (context.context === 'JavaScript') {
    if (context.quote && has(context.quote)) {
      return {
        severity: SEVERITY.HIGH,
        confidence: CONFIDENCE.HIGH,
        rationale: `the ${context.quote === '"' ? 'double' : 'single'} quote that terminates the surrounding JavaScript string literal is reflected unencoded, so input can escape the string and be interpreted as code`,
      };
    }
    if (!context.quote && surviving.length > 0) {
      return {
        severity: SEVERITY.HIGH,
        confidence: CONFIDENCE.HIGH,
        rationale: 'the value is written directly into script code with markup-significant characters unencoded',
      };
    }
    if (tagBreakout) {
      return {
        severity: SEVERITY.HIGH,
        confidence: CONFIDENCE.MEDIUM,
        rationale: 'angle brackets survive inside a <script> block, which allows the script element to be closed early',
      };
    }
    return null;
  }

  if (context.context === 'Event handler attribute') {
    if (surviving.length > 0) {
      return {
        severity: SEVERITY.HIGH,
        confidence: CONFIDENCE.HIGH,
        rationale: 'the value is reflected into an event-handler attribute with unencoded characters, which places attacker input directly in a JavaScript execution context',
      };
    }
    return null;
  }

  if (context.context === 'HTML attribute' || context.context === 'URL attribute') {
    if (context.quote && has(context.quote)) {
      return {
        severity: SEVERITY.HIGH,
        confidence: CONFIDENCE.HIGH,
        rationale: `the ${context.quote === '"' ? 'double' : 'single'} quote that delimits the attribute value is reflected unencoded, so input can close the attribute and introduce new ones (for example an event handler)`,
      };
    }
    if (!context.quote && surviving.length > 0) {
      return {
        severity: SEVERITY.HIGH,
        confidence: CONFIDENCE.MEDIUM,
        rationale: 'the attribute value is unquoted and markup-significant characters are reflected unencoded, so input can add further attributes',
      };
    }
    if (tagBreakout) {
      return {
        severity: SEVERITY.HIGH,
        confidence: CONFIDENCE.MEDIUM,
        rationale: 'angle brackets are reflected unencoded inside a tag',
      };
    }
    return null;
  }

  if (context.context === 'HTML text') {
    if (tagBreakout) {
      return {
        severity: SEVERITY.HIGH,
        confidence: CONFIDENCE.HIGH,
        rationale: 'both angle brackets are reflected unencoded in HTML text, so input is parsed as markup rather than text',
      };
    }
    if (has('<')) {
      return {
        severity: SEVERITY.MEDIUM,
        confidence: CONFIDENCE.MEDIUM,
        rationale: 'the "<" character is reflected unencoded in HTML text, which is the first requirement for markup injection',
      };
    }
    return null;
  }

  if (context.context === 'HTML comment' && tagBreakout) {
    return {
      severity: SEVERITY.MEDIUM,
      confidence: CONFIDENCE.MEDIUM,
      rationale: 'angle brackets survive inside an HTML comment, which may allow the comment to be closed early',
    };
  }

  return null;
}

/**
 * Run reflection analysis for one injection point.
 * @param {import('../services/scanContext.js').ScanContext} ctx
 * @param {object} point
 */
export async function checkXss(ctx, point) {
  const token = canaryToken('xss');

  // Step 1 - is the parameter reflected at all?
  const plain = await sendProbe(ctx, point, token, 'xss-canary');
  if (!plain.ok || !plain.body) return;
  if (!plain.body.toLowerCase().includes(token)) return;

  // Step 2 - do markup-significant characters survive, and where?
  const probeValue = `${token}${PROBE_SUFFIX}`;
  const probe = await sendProbe(ctx, point, probeValue, 'xss-context');
  if (!probe.ok || !probe.body) return;

  const body = probe.body;
  const occurrences = findOccurrences(body, token, 5);
  if (occurrences.length === 0) {
    reportEncodedReflection(ctx, point, plain, token);
    return;
  }

  const regions = specialRegions(body);
  let best = null;

  for (const index of occurrences) {
    const context = determineContext(body, index, regions);
    const surviving = survivingCharacters(body, index, token);
    const verdict = assess(context, surviving);
    if (!verdict) continue;

    const rank = (verdict.confidence === CONFIDENCE.HIGH ? 2 : 1) + (verdict.severity === SEVERITY.HIGH ? 2 : 0);
    if (!best || rank > best.rank) {
      best = { rank, index, context, surviving, verdict };
    }
  }

  if (!best) {
    reportEncodedReflection(ctx, point, probe, token);
    return;
  }

  const encodedList = PROBE_CHARS.filter((char) => !best.surviving.includes(char));

  ctx.addFinding({
    type: 'Reflected XSS',
    severity: best.verdict.severity,
    confidence: best.verdict.confidence,
    url: probe.url,
    parameter: point.parameter,
    method: point.method,
    description:
      `The value of "${point.parameter}" is reflected into the response ${best.context.detail}. ` +
      `A test value of ${JSON.stringify(probeValue)} was sent and ${best.verdict.rationale}. ` +
      `Characters returned unencoded: ${best.surviving.join(' ')}` +
      (encodedList.length ? `; correctly encoded: ${encodedList.join(' ')}.` : '.') +
      ' No script payload was executed - this finding is based on encoding behaviour only, so confirm it manually before remediating.',
    evidence:
      `Probe value: ${probeValue}\n` +
      `Context: ${best.context.context} (${best.context.detail})\n` +
      `Unencoded characters: ${best.surviving.join(' ') || 'none'}\n` +
      `Response snippet: ${excerpt(body, best.index, 110)}`,
    recommendation: RECOMMENDATION,
    references: ['https://owasp.org/www-community/attacks/xss/', 'CWE-79'],
  });
}

/** Reflection with correct encoding: worth knowing about, not a vulnerability. */
function reportEncodedReflection(ctx, point, response, token) {
  const index = findOccurrences(response.body, token, 1)[0];
  ctx.addFinding({
    type: 'Reflected Parameter Value',
    severity: SEVERITY.INFO,
    confidence: CONFIDENCE.LOW,
    url: response.url,
    parameter: point.parameter,
    method: point.method,
    description:
      `The value of "${point.parameter}" is echoed back in the response, but the markup-significant characters ` +
      `sent with the probe were encoded or filtered. This is expected, safe behaviour and is reported only as an ` +
      `inventory of user-controlled output. It is not evidence of cross-site scripting.`,
    evidence: index === undefined ? `Canary ${token} reflected.` : excerpt(response.body, index, 110),
    recommendation:
      'No action required if the encoding is applied by the framework for every context. Verify that the same ' +
      'encoding is used wherever this parameter is rendered (HTML, attributes, JavaScript, URLs).',
    references: ['CWE-79'],
  });
}
