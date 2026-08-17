/**
 * Minimal robots.txt support.
 *
 * Honouring robots.txt is part of scanning politely. It is not a security
 * control - it exists so the scanner does not wander into areas the site owner
 * has asked automated clients to leave alone.
 */
const AGENT_TOKEN = 'vulnscanner';

/** Convert a robots path pattern (supports `*` and `$`) into a RegExp. */
function patternToRegExp(pattern) {
  const escaped = pattern
    .replace(/[.+?^${}()|[\]\\]/g, '\\$&')
    .replace(/\*/g, '.*');
  const anchored = escaped.endsWith('\\$') ? `^${escaped.slice(0, -2)}$` : `^${escaped}`;
  return new RegExp(anchored);
}

export function parseRobots(text = '') {
  const groups = [];
  let current = null;
  let expectingAgent = false;

  for (const rawLine of String(text).split(/\r?\n/)) {
    const line = rawLine.replace(/#.*$/, '').trim();
    if (!line) continue;
    const separator = line.indexOf(':');
    if (separator === -1) continue;

    const field = line.slice(0, separator).trim().toLowerCase();
    const value = line.slice(separator + 1).trim();

    if (field === 'user-agent') {
      if (!current || !expectingAgent) {
        current = { agents: [], rules: [], crawlDelay: null };
        groups.push(current);
        expectingAgent = true;
      }
      current.agents.push(value.toLowerCase());
      continue;
    }

    if (!current) continue;
    expectingAgent = false;

    if (field === 'disallow' || field === 'allow') {
      // "Disallow:" with an empty value means "allow everything".
      if (field === 'disallow' && value === '') continue;
      current.rules.push({ allow: field === 'allow', path: value, matcher: patternToRegExp(value) });
    } else if (field === 'crawl-delay') {
      const delay = Number.parseFloat(value);
      if (Number.isFinite(delay)) current.crawlDelay = delay;
    }
  }

  return groups;
}

export class RobotsPolicy {
  constructor(groups = [], { available = true } = {}) {
    const matching = groups.filter((group) =>
      group.agents.some((agent) => agent !== '*' && agent.length > 0 && AGENT_TOKEN.includes(agent)),
    );
    const wildcard = groups.filter((group) => group.agents.includes('*'));
    const selected = matching.length > 0 ? matching : wildcard;

    this.rules = selected.flatMap((group) => group.rules);
    this.crawlDelayMs = selected.reduce((max, group) => {
      const delay = group.crawlDelay ? group.crawlDelay * 1000 : 0;
      return Math.max(max, delay);
    }, 0);
    this.available = available;
  }

  /**
   * Longest-match wins; an Allow rule beats a Disallow rule of the same length.
   */
  isAllowed(input) {
    if (this.rules.length === 0) return true;
    let pathname;
    try {
      const url = input instanceof URL ? input : new URL(input);
      pathname = `${url.pathname}${url.search}`;
    } catch {
      return true;
    }

    let best = null;
    for (const rule of this.rules) {
      if (!rule.matcher.test(pathname)) continue;
      const length = rule.path.length;
      if (!best || length > best.length || (length === best.length && rule.allow)) {
        best = { length, allow: rule.allow };
      }
    }
    return best ? best.allow : true;
  }
}

/** Always resolves - a missing or broken robots.txt simply allows everything. */
export async function loadRobots(httpClient, origin) {
  try {
    const response = await httpClient.get(`${origin}/robots.txt`, { purpose: 'robots' });
    if (!response.ok || response.status !== 200 || !response.body) {
      return new RobotsPolicy([], { available: false });
    }
    if (response.contentType && !/text\/plain|text\//i.test(response.contentType)) {
      return new RobotsPolicy([], { available: false });
    }
    return new RobotsPolicy(parseRobots(response.body), { available: true });
  } catch {
    return new RobotsPolicy([], { available: false });
  }
}
