/**
 * HTML / JavaScript extraction.
 *
 * Turns a fetched document into the raw material the crawler and the scanner
 * work with: links to follow, forms to inspect and API-looking endpoints
 * referenced from scripts.
 */
import * as cheerio from 'cheerio';
import { normalizeUrl, isSkippableAsset } from '../utils/url.js';

/** Attributes that commonly carry a URL. */
const URL_ATTRIBUTES = [
  ['a', 'href'],
  ['area', 'href'],
  ['iframe', 'src'],
  ['frame', 'src'],
  ['link[rel="canonical"]', 'href'],
  ['link[rel="alternate"]', 'href'],
  // Pagination hints. Following these is often the only way to reach page 2
  // onwards of an archive or a product listing.
  ['link[rel="next"]', 'href'],
  ['link[rel="prev"]', 'href'],
  ['form', 'action'],
  ['[data-url]', 'data-url'],
  ['[data-href]', 'data-href'],
  ['[data-api]', 'data-api'],
];

/** Explicit client-side calls: fetch(...), axios.get(...), xhr.open('GET', ...). */
const CALL_PATTERNS = [
  /\bfetch\s*\(\s*['"`]([^'"`]{1,300})['"`]/gi,
  /\baxios\s*\.\s*(?:get|post|put|patch|delete|request)\s*\(\s*['"`]([^'"`]{1,300})['"`]/gi,
  /\baxios\s*\(\s*\{[^}]{0,200}?url\s*:\s*['"`]([^'"`]{1,300})['"`]/gi,
  /\.open\s*\(\s*['"`][A-Z]+['"`]\s*,\s*['"`]([^'"`]{1,300})['"`]/gi,
  /\$\.(?:get|post|ajax|getJSON)\s*\(\s*['"`]([^'"`]{1,300})['"`]/gi,
  /\burl\s*:\s*['"`](\/[^'"`]{1,300})['"`]/gi,
];

/** Bare string literals that look like API routes. */
const ROUTE_PATTERNS = [
  /['"`](\/(?:api|apis|v\d+|rest|graphql|gql|ajax|rpc|service|services)\/[^'"`\s<>]{1,200})['"`]/gi,
  /['"`](\/[a-z0-9._~-]+(?:\/[a-z0-9._~-]+){0,6}\.(?:json|php|aspx?|jsp|do|action|cgi))(\?[^'"`\s<>]{0,150})?['"`]/gi,
];

const isLikelyTemplateLiteral = (value) => /\$\{|\{\{|<%|%>/.test(value);

/**
 * @param {string} html
 * @param {string} baseUrl
 * @returns {{title: string, links: string[], forms: object[], scripts: string[], apiCandidates: string[], meta: object}}
 */
export function parseHtml(html, baseUrl) {
  const $ = cheerio.load(html, { decodeEntities: false });

  // A <base href> changes how every relative URL on the page resolves.
  const baseHref = $('base[href]').first().attr('href');
  let resolvedBase = baseUrl;
  if (baseHref) {
    const candidate = normalizeUrl(baseHref, baseUrl);
    if (candidate) resolvedBase = candidate.href;
  }

  const links = new Set();
  const scripts = new Set();
  const apiCandidates = new Set();

  for (const [selector, attribute] of URL_ATTRIBUTES) {
    $(selector).each((_, element) => {
      const value = $(element).attr(attribute);
      if (!value || isLikelyTemplateLiteral(value)) return;
      const url = normalizeUrl(value, resolvedBase);
      if (url) links.add(url.href);
    });
  }

  $('script[src]').each((_, element) => {
    const url = normalizeUrl($(element).attr('src'), resolvedBase);
    if (url) scripts.add(url.href);
  });

  $('script:not([src])').each((_, element) => {
    const code = $(element).html() || '';
    for (const candidate of extractEndpointsFromScript(code, resolvedBase)) {
      apiCandidates.add(candidate);
    }
  });

  const forms = [];
  $('form').each((_, element) => {
    const form = parseForm($, element, resolvedBase);
    if (form) forms.push(form);
  });

  return {
    title: ($('title').first().text() || '').trim().slice(0, 200),
    links: [...links],
    forms,
    scripts: [...scripts],
    apiCandidates: [...apiCandidates],
    meta: {
      generator: $('meta[name="generator"]').attr('content') || '',
      hasPasswordField: $('input[type="password"]').length > 0,
      csp: $('meta[http-equiv="Content-Security-Policy"]').attr('content') || '',
    },
  };
}

function parseForm($, element, baseUrl) {
  const $form = $(element);
  const action = $form.attr('action');
  const target = normalizeUrl(action === undefined || action === '' ? baseUrl : action, baseUrl);
  if (!target) return null;

  const inputs = [];
  $form.find('input, textarea, select').each((_, field) => {
    const $field = $(field);
    const name = $field.attr('name');
    if (!name) return;
    const tag = (field.tagName || field.name || '').toLowerCase();
    const type = tag === 'input' ? ($field.attr('type') || 'text').toLowerCase() : tag;
    inputs.push({
      name,
      type,
      value: type === 'password' ? '' : ($field.attr('value') || '').slice(0, 120),
      required: $field.attr('required') !== undefined,
    });
  });

  return {
    method: ($form.attr('method') || 'GET').toUpperCase() === 'POST' ? 'POST' : 'GET',
    action: target.href,
    enctype: ($form.attr('enctype') || 'application/x-www-form-urlencoded').toLowerCase(),
    id: $form.attr('id') || '',
    name: $form.attr('name') || '',
    inputs,
  };
}

/**
 * Pull endpoint-looking strings out of JavaScript. This is best-effort pattern
 * matching, so every result is treated as a *candidate* until a request to it
 * returns a real status code.
 */
export function extractEndpointsFromScript(code, baseUrl) {
  const found = new Set();
  const source = String(code).slice(0, 400_000);

  const collect = (patterns) => {
    for (const pattern of patterns) {
      pattern.lastIndex = 0;
      let match = pattern.exec(source);
      while (match !== null) {
        const raw = match[1];
        if (raw && !isLikelyTemplateLiteral(raw)) {
          const url = normalizeUrl(raw, baseUrl);
          if (url && !isSkippableAsset(url)) found.add(url.href);
        }
        match = pattern.exec(source);
      }
    }
  };

  collect(CALL_PATTERNS);
  collect(ROUTE_PATTERNS);
  return [...found];
}

/** Parse a Set-Cookie header value into name + flags (used by passive checks). */
export function parseCookie(header) {
  const [pair, ...attributes] = String(header).split(';');
  const separator = pair.indexOf('=');
  const name = separator === -1 ? pair.trim() : pair.slice(0, separator).trim();
  const flags = attributes.map((attribute) => attribute.trim().toLowerCase());
  const sameSite = flags.find((flag) => flag.startsWith('samesite='));

  return {
    name,
    secure: flags.includes('secure'),
    httpOnly: flags.includes('httponly'),
    sameSite: sameSite ? sameSite.split('=')[1] : null,
  };
}
