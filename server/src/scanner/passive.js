/**
 * Passive checks.
 *
 * These run on responses the crawler has already fetched - they cost no extra
 * requests and send nothing to the target. Findings are deduplicated per origin
 * (or per cookie / per form) so a site-wide misconfiguration is reported once
 * rather than on all 100 crawled pages.
 */
import { SEVERITY, CONFIDENCE } from '../config/index.js';
import { excerpt } from '../utils/text.js';
import { parseCookie } from '../crawler/parser.js';
import { reportDatabaseErrorInBody } from './sqli.js';
import {
  DIRECTORY_LISTING,
  STACK_TRACES,
  PATH_DISCLOSURE,
  matchAny,
  matchSignatures,
} from './signatures.js';

/** Hidden inputs that look like an anti-CSRF token. */
const CSRF_FIELD = /(csrf|xsrf|_token|authenticity_token|nonce|requestverificationtoken)/i;

const originOf = (url) => {
  try {
    return new URL(url).origin;
  } catch {
    return url;
  }
};

/**
 * @param {import('../services/scanContext.js').ScanContext} ctx
 * @param {object} response result from ScannerHttpClient
 * @param {object|null} parsed result from parseHtml (null for non-HTML)
 */
export function runPassiveChecks(ctx, response, parsed) {
  if (!response.ok) return;
  const origin = originOf(response.url);
  const isHttps = response.url.startsWith('https:');
  const headers = response.headers || {};
  const isHtml = Boolean(parsed);

  if (isHtml) checkSecurityHeaders(ctx, response, headers, origin, isHttps, parsed);
  checkCookies(ctx, response, headers, origin, isHttps);
  checkVersionDisclosure(ctx, response, headers, origin);
  checkErrorDisclosure(ctx, response, origin);
  if (isHtml) checkForms(ctx, response, parsed, isHttps);
  if (isHtml) checkMixedContent(ctx, response, parsed, isHttps);
}

// --- response headers -------------------------------------------------------

function checkSecurityHeaders(ctx, response, headers, origin, isHttps, parsed) {
  const csp = headers['content-security-policy'] || parsed.meta.csp || '';

  if (!csp) {
    ctx.addFinding({
      type: 'Missing Content-Security-Policy',
      severity: SEVERITY.LOW,
      confidence: CONFIDENCE.HIGH,
      url: origin,
      method: 'GET',
      dedupeKey: `header|csp|${origin}`,
      description:
        'No Content-Security-Policy header is set. CSP is the main defence-in-depth control against cross-site ' +
        'scripting: without it, any successful injection runs with the full privileges of the page, and there is ' +
        'no restriction on where scripts, frames or form submissions may come from.',
      evidence: `GET ${response.url} -> HTTP ${response.status}, no Content-Security-Policy response header.`,
      recommendation:
        "Add a Content-Security-Policy header. Start in report-only mode to find breakage, then enforce a policy " +
        "such as default-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'self', avoiding " +
        "'unsafe-inline' and 'unsafe-eval'.",
      references: ['CWE-1021', 'https://owasp.org/www-project-secure-headers/'],
    });
  }

  const frameAncestors = /frame-ancestors/i.test(csp);
  if (!headers['x-frame-options'] && !frameAncestors) {
    ctx.addFinding({
      type: 'Missing Clickjacking Protection',
      severity: SEVERITY.MEDIUM,
      confidence: CONFIDENCE.HIGH,
      url: origin,
      method: 'GET',
      dedupeKey: `header|frame|${origin}`,
      description:
        'The response sets neither X-Frame-Options nor a CSP frame-ancestors directive, so the page can be framed ' +
        'by any site. An attacker can overlay an invisible frame of this application on their own page and trick ' +
        'a logged-in user into clicking controls they cannot see (clickjacking).',
      evidence: `GET ${response.url} -> HTTP ${response.status}, no X-Frame-Options and no CSP frame-ancestors.`,
      recommendation:
        "Send Content-Security-Policy: frame-ancestors 'none' (or 'self', or an explicit list of allowed parents). " +
        'Keep X-Frame-Options: DENY alongside it for older browsers.',
      references: ['CWE-1021'],
    });
  }

  if (!headers['x-content-type-options']) {
    ctx.addFinding({
      type: 'Missing X-Content-Type-Options',
      severity: SEVERITY.LOW,
      confidence: CONFIDENCE.HIGH,
      url: origin,
      method: 'GET',
      dedupeKey: `header|nosniff|${origin}`,
      description:
        'X-Content-Type-Options: nosniff is not set. Browsers may then MIME-sniff a response and treat it as a ' +
        'different type than declared - user-uploaded content served with the wrong Content-Type can end up being ' +
        'interpreted as HTML or JavaScript.',
      evidence: `GET ${response.url} -> HTTP ${response.status}, no X-Content-Type-Options header.`,
      recommendation: 'Send X-Content-Type-Options: nosniff on every response, and set accurate Content-Type headers.',
      references: ['CWE-16'],
    });
  }

  if (isHttps && !headers['strict-transport-security']) {
    ctx.addFinding({
      type: 'Missing HTTP Strict Transport Security',
      severity: SEVERITY.LOW,
      confidence: CONFIDENCE.HIGH,
      url: origin,
      method: 'GET',
      dedupeKey: `header|hsts|${origin}`,
      description:
        'This HTTPS site does not send a Strict-Transport-Security header. Until a user has been redirected to ' +
        'HTTPS at least once per session, an initial plaintext request can be intercepted and downgraded.',
      evidence: `GET ${response.url} -> HTTP ${response.status}, no Strict-Transport-Security header.`,
      recommendation:
        'Send Strict-Transport-Security: max-age=31536000; includeSubDomains (add preload once you are certain ' +
        'every subdomain supports HTTPS).',
      references: ['CWE-319'],
    });
  }

  if (!headers['referrer-policy']) {
    ctx.addFinding({
      type: 'Missing Referrer-Policy',
      severity: SEVERITY.INFO,
      confidence: CONFIDENCE.HIGH,
      url: origin,
      method: 'GET',
      dedupeKey: `header|referrer|${origin}`,
      description:
        'No Referrer-Policy is set, so the browser default applies and full URLs may be sent to third-party sites ' +
        'in the Referer header. Where URLs contain identifiers or tokens, that leaks them off-site.',
      evidence: `GET ${response.url} -> HTTP ${response.status}, no Referrer-Policy header.`,
      recommendation: 'Send Referrer-Policy: strict-origin-when-cross-origin (or no-referrer for sensitive areas).',
      references: ['CWE-200'],
    });
  }
}

// --- cookies ----------------------------------------------------------------

function checkCookies(ctx, response, headers, origin, isHttps) {
  const raw = headers['set-cookie'];
  if (!raw) return;
  const cookies = Array.isArray(raw) ? raw : [raw];

  for (const header of cookies) {
    const cookie = parseCookie(header);
    if (!cookie.name) continue;
    const looksLikeSession = /(sess|sid|auth|login|token|user)/i.test(cookie.name);
    const redacted = `${cookie.name}=<redacted>; ${header.split(';').slice(1).join(';').trim()}`;

    if (isHttps && !cookie.secure) {
      ctx.addFinding({
        type: 'Cookie Without Secure Flag',
        severity: looksLikeSession ? SEVERITY.MEDIUM : SEVERITY.LOW,
        confidence: CONFIDENCE.HIGH,
        url: origin,
        parameter: cookie.name,
        method: 'GET',
        dedupeKey: `cookie|secure|${origin}|${cookie.name}`,
        description:
          `The cookie "${cookie.name}" is set over HTTPS without the Secure attribute, so the browser will also ` +
          `send it over plain HTTP. Any downgraded or mixed-content request exposes its value on the network.`,
        evidence: redacted,
        recommendation: 'Add the Secure attribute to every cookie set over HTTPS.',
        references: ['CWE-614'],
      });
    }

    if (!cookie.httpOnly && looksLikeSession) {
      ctx.addFinding({
        type: 'Session Cookie Without HttpOnly',
        severity: SEVERITY.MEDIUM,
        confidence: CONFIDENCE.MEDIUM,
        url: origin,
        parameter: cookie.name,
        method: 'GET',
        dedupeKey: `cookie|httponly|${origin}|${cookie.name}`,
        description:
          `The session-like cookie "${cookie.name}" is readable from JavaScript because HttpOnly is not set. ` +
          `If the application ever has a cross-site scripting flaw, that flaw becomes session theft.`,
        evidence: redacted,
        recommendation:
          'Set HttpOnly on session and authentication cookies. Only omit it for cookies a script genuinely needs.',
        references: ['CWE-1004'],
      });
    }

    if (!cookie.sameSite) {
      ctx.addFinding({
        type: 'Cookie Without SameSite Attribute',
        severity: SEVERITY.LOW,
        confidence: CONFIDENCE.MEDIUM,
        url: origin,
        parameter: cookie.name,
        method: 'GET',
        dedupeKey: `cookie|samesite|${origin}|${cookie.name}`,
        description:
          `The cookie "${cookie.name}" has no SameSite attribute. Browser defaults vary, and where the cookie is ` +
          `sent on cross-site requests it can be used to ride an authenticated session (CSRF).`,
        evidence: redacted,
        recommendation: 'Set SameSite=Lax (or Strict), and SameSite=None; Secure only where cross-site use is required.',
        references: ['CWE-1275'],
      });
    }
  }
}

// --- fingerprinting ---------------------------------------------------------

function checkVersionDisclosure(ctx, response, headers, origin) {
  for (const name of ['server', 'x-powered-by', 'x-aspnet-version', 'x-generator']) {
    const value = headers[name];
    // Only report when a version number is actually present.
    if (!value || !/\d+\.\d+/.test(String(value))) continue;

    ctx.addFinding({
      type: 'Technology Version Disclosure',
      severity: SEVERITY.INFO,
      confidence: CONFIDENCE.HIGH,
      url: origin,
      parameter: name,
      method: 'GET',
      dedupeKey: `version|${origin}|${name}|${value}`,
      description:
        `The "${name}" response header advertises a precise software version (${value}). That tells an attacker ` +
        `exactly which published vulnerabilities to try first. It is not a vulnerability by itself.`,
      evidence: `${name}: ${value}`,
      recommendation:
        'Suppress or genericise version banners (server_tokens off in nginx, ServerTokens Prod in Apache, remove ' +
        'X-Powered-By in the application framework) and keep the software patched.',
      references: ['CWE-200'],
    });
  }
}

// --- error / listing disclosure ---------------------------------------------

function checkErrorDisclosure(ctx, response, origin) {
  if (!response.body) return;

  const listing = matchAny(response.body, DIRECTORY_LISTING);
  if (listing) {
    ctx.addFinding({
      type: 'Directory Listing Enabled',
      severity: SEVERITY.MEDIUM,
      confidence: CONFIDENCE.HIGH,
      url: response.url,
      method: 'GET',
      description:
        'The server returned an automatically generated directory index. Directory listings expose files that were ' +
        'never meant to be linked - backups, exports, configuration and old versions - and give an attacker a map ' +
        'of the deployment.',
      evidence: listing,
      recommendation:
        'Disable automatic indexes (autoindex off in nginx, Options -Indexes in Apache) and place an index file in ' +
        'every served directory.',
      references: ['CWE-548'],
    });
  }

  const trace = matchSignatures(response.body, STACK_TRACES, 'platform');
  if (trace.matched) {
    const index = response.body.indexOf(trace.match);
    ctx.addFinding({
      type: 'Verbose Error / Stack Trace Disclosure',
      severity: SEVERITY.MEDIUM,
      confidence: CONFIDENCE.MEDIUM,
      url: response.url,
      method: 'GET',
      dedupeKey: `stacktrace|${origin}|${trace.label}`,
      description:
        `The response contains a ${trace.label || 'framework'} stack trace or debug output. Traces reveal internal ` +
        `file paths, library versions and code structure, and their presence usually means debug mode is enabled ` +
        `in an environment that is reachable from the internet.`,
      evidence: index >= 0 ? excerpt(response.body, index, 140) : trace.match,
      recommendation:
        'Disable debug mode in production, return generic error pages, and send exception detail to server-side logs only.',
      references: ['CWE-209'],
    });
  }

  const path = matchAny(response.body, PATH_DISCLOSURE);
  if (path && (trace.matched || /error|warning|exception/i.test(response.body.slice(0, 4000)))) {
    ctx.addFinding({
      type: 'Server Path Disclosure',
      severity: SEVERITY.LOW,
      confidence: CONFIDENCE.MEDIUM,
      url: response.url,
      method: 'GET',
      dedupeKey: `pathdisclosure|${origin}`,
      description:
        `An absolute filesystem path (${path}) appears in the response. Knowing the deployment layout makes file ` +
        `inclusion, traversal and upload attacks considerably easier to aim.`,
      evidence: path,
      recommendation: 'Suppress filesystem paths in client-facing output; log them server-side instead.',
      references: ['CWE-200'],
    });
  }

  reportDatabaseErrorInBody(ctx, response);
}

// --- forms ------------------------------------------------------------------

function checkForms(ctx, response, parsed, isHttps) {
  for (const form of parsed.forms) {
    const actionIsHttp = form.action.startsWith('http:');
    const hasPassword = form.inputs.some((input) => input.type === 'password');

    if (hasPassword && (actionIsHttp || !isHttps)) {
      ctx.addFinding({
        type: 'Credentials Submitted Over HTTP',
        severity: SEVERITY.HIGH,
        confidence: CONFIDENCE.HIGH,
        url: form.action,
        method: form.method,
        dedupeKey: `form|http-password|${form.action}`,
        description:
          'A form containing a password field is served or submitted over plain HTTP. Credentials sent this way ' +
          'are readable by anyone on the network path and can be modified in transit.',
        evidence: `Form action: ${form.action} (method ${form.method}), page: ${response.url}`,
        recommendation:
          'Serve the page and post the form over HTTPS only, redirect HTTP to HTTPS, and enable HSTS.',
        references: ['CWE-319'],
      });
    } else if (isHttps && actionIsHttp) {
      ctx.addFinding({
        type: 'Form Submits to Insecure URL',
        severity: SEVERITY.MEDIUM,
        confidence: CONFIDENCE.HIGH,
        url: form.action,
        method: form.method,
        dedupeKey: `form|http-action|${form.action}`,
        description:
          'A form on an HTTPS page posts to an http:// URL, so its contents leave the browser unencrypted.',
        evidence: `Form action: ${form.action}, page: ${response.url}`,
        recommendation: 'Point the form action at an https:// URL (or a same-origin relative path).',
        references: ['CWE-319'],
      });
    }

    if (form.method === 'POST') {
      const hasToken = form.inputs.some((input) => CSRF_FIELD.test(input.name));
      if (!hasToken) {
        ctx.addFinding({
          type: 'Form Without CSRF Token',
          severity: SEVERITY.LOW,
          confidence: CONFIDENCE.LOW,
          url: form.action,
          method: 'POST',
          dedupeKey: `form|csrf|${form.action}`,
          description:
            'This POST form contains no hidden field that looks like an anti-CSRF token. If the endpoint changes ' +
            'state and relies only on cookies for authentication, another site could submit it on a logged-in ' +
            "user's behalf. Confidence is low: the protection may come from SameSite cookies, a custom header, or " +
            'a token this check does not recognise.',
          evidence: `Form action: ${form.action}, fields: ${form.inputs.map((input) => input.name).join(', ') || 'none'}`,
          recommendation:
            'Use the framework\'s CSRF protection (synchroniser token or double-submit cookie) on every state-changing ' +
            'request, and set SameSite=Lax or Strict on session cookies.',
          references: ['CWE-352'],
        });
      }
    }
  }
}

function checkMixedContent(ctx, response, parsed, isHttps) {
  if (!isHttps) return;
  const insecure = parsed.scripts.filter((src) => src.startsWith('http:'));
  if (insecure.length === 0) return;

  ctx.addFinding({
    type: 'Mixed Content',
    severity: SEVERITY.LOW,
    confidence: CONFIDENCE.HIGH,
    url: response.url,
    method: 'GET',
    dedupeKey: `mixed|${originOf(response.url)}`,
    description:
      'An HTTPS page loads scripts over plain HTTP. Modern browsers block this, and where it is not blocked an ' +
      'attacker on the network can replace the script and take over the page.',
    evidence: insecure.slice(0, 5).join('\n'),
    recommendation: 'Load every subresource over HTTPS and add upgrade-insecure-requests to your CSP.',
    references: ['CWE-311'],
  });
}
