/**
 * Injection points: the (endpoint, parameter) pairs the detection modules test.
 *
 * Building them once, here, means the XSS / SQLi / traversal modules never have
 * to know whether a value travels in a query string or a form body.
 */
import { getQueryParameters } from '../utils/url.js';

/** Maximum number of parameters tested in a single scan. */
const MAX_POINTS = 80;

/**
 * Parameters that carry secrets or anti-CSRF state. Sending probe values here
 * is pointless and would mean handling other people's tokens, so they are
 * skipped entirely.
 */
const SENSITIVE_PARAMETER = /(csrf|xsrf|token|nonce|auth|session|sid$|^sid|jwt|bearer|api[_-]?key|apikey|password|passwd|pwd|secret|signature|otp|captcha)/i;

/** Forms whose action suggests a state change - not submitted automatically. */
const SENSITIVE_ACTION = /(login|signin|sign-in|logout|register|signup|sign-up|password|checkout|payment|pay|order|delete|remove|destroy|upload|admin|subscribe|unsubscribe|contact|comment|review)/i;

const DEFAULT_BY_TYPE = {
  email: 'scanner@example.com',
  number: '1',
  range: '1',
  tel: '5551234567',
  url: 'https://example.com',
  date: '2024-01-01',
  'datetime-local': '2024-01-01T00:00',
  month: '2024-01',
  week: '2024-W01',
  time: '00:00',
  color: '#000000',
  checkbox: 'on',
  radio: 'on',
  search: 'test',
  textarea: 'test',
  select: 'test',
};

const TESTABLE_INPUT = /^(text|search|url|email|tel|number|hidden|textarea|select|date|month|week|time|range|color|checkbox|radio)$/;

const defaultValueFor = (input) =>
  input.value || DEFAULT_BY_TYPE[input.type] || 'test';

/**
 * @param {import('../services/scanContext.js').ScanContext} ctx
 * @returns {{points: object[], skipped: string[]}}
 */
export function buildInjectionPoints(ctx) {
  const points = [];
  const skipped = [];
  const seen = new Set();

  const add = (point) => {
    const key = `${point.method} ${point.url}|${point.parameter}`;
    if (seen.has(key) || points.length >= MAX_POINTS) return;
    seen.add(key);
    points.push(point);
  };

  for (const endpoint of ctx.endpoints) {
    // --- query string parameters -----------------------------------------
    if (endpoint.method === 'GET') {
      let url;
      try {
        url = new URL(endpoint.url);
      } catch {
        continue;
      }
      const fields = Object.fromEntries(url.searchParams.entries());

      for (const parameter of getQueryParameters(url)) {
        if (SENSITIVE_PARAMETER.test(parameter)) {
          skipped.push(`${parameter} (sensitive parameter name)`);
          continue;
        }
        add({
          endpointId: endpoint.id,
          url: `${url.origin}${url.pathname}`,
          displayUrl: endpoint.url,
          method: 'GET',
          parameter,
          source: 'query',
          fields,
          baseValue: fields[parameter] ?? '',
        });
      }
    }

    // --- form inputs -------------------------------------------------------
    if (!ctx.config.testForms) continue;

    for (const form of endpoint.forms || []) {
      const hasPassword = form.inputs.some((input) => input.type === 'password');
      if (hasPassword) {
        skipped.push(`${form.action} (form contains a password field)`);
        continue;
      }
      if (form.method === 'POST') {
        if (!ctx.config.testPostForms) {
          skipped.push(`${form.action} (POST form - enable "test POST forms" to include)`);
          continue;
        }
        if (SENSITIVE_ACTION.test(form.action)) {
          skipped.push(`${form.action} (POST form with a state-changing action)`);
          continue;
        }
      }
      if (form.enctype && form.enctype.includes('multipart')) {
        skipped.push(`${form.action} (file upload form)`);
        continue;
      }

      const fields = {};
      for (const input of form.inputs) {
        if (input.type === 'submit' || input.type === 'button' || input.type === 'file') continue;
        fields[input.name] = defaultValueFor(input);
      }

      for (const input of form.inputs) {
        if (!TESTABLE_INPUT.test(input.type)) continue;
        if (SENSITIVE_PARAMETER.test(input.name)) {
          skipped.push(`${input.name} (sensitive form field)`);
          continue;
        }
        add({
          endpointId: endpoint.id,
          url: form.action,
          displayUrl: form.action,
          method: form.method,
          parameter: input.name,
          source: 'form',
          fields,
          baseValue: fields[input.name] ?? '',
          inputType: input.type,
        });
      }
    }
  }

  return { points, skipped: [...new Set(skipped)] };
}

/**
 * Send one probe value through an injection point.
 * @param {import('../services/scanContext.js').ScanContext} ctx
 * @param {object} point
 * @param {string} value
 */
export function sendProbe(ctx, point, value, purpose = 'probe') {
  const fields = { ...point.fields, [point.parameter]: value };

  if (point.method === 'POST') {
    return ctx.http.postForm(point.url, fields, { purpose });
  }

  const url = new URL(point.url);
  for (const [name, fieldValue] of Object.entries(fields)) {
    url.searchParams.set(name, fieldValue);
  }
  return ctx.http.get(url.href, { purpose });
}

/** Human readable label for logs and finding descriptions. */
export const describePoint = (point) =>
  `${point.method} ${point.url} [${point.parameter}]`;
