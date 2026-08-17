/**
 * SSRF guard.
 *
 * Two layers of protection:
 *
 *  1. `assertSafeUrl()` - a pre-flight check on scheme, port, hostname shape and
 *     the resolved DNS records. Gives the user a clear error before a scan starts.
 *  2. `safeLookup()` - installed as the DNS resolver on the HTTP agents, so the
 *     address the socket actually connects to is validated at connect time.
 *     This is what closes the DNS-rebinding window: a name that resolves to a
 *     public IP during validation and to 127.0.0.1 a second later still fails,
 *     because the check runs on the address the connection will use.
 */
import dns from 'node:dns';
import net from 'node:net';
import { classifyIp } from './ipRules.js';
import { BlockedTargetError } from '../utils/errors.js';
import { SERVER_CONFIG } from '../config/index.js';

/**
 * Private targets are refused unless the operator started the process with
 * ALLOW_PRIVATE_TARGETS=true (see config/index.js). Read through this helper so
 * there is exactly one place where the exemption applies.
 */
const privateTargetsAllowed = () => SERVER_CONFIG.allowPrivateTargets === true;

const ALLOWED_PROTOCOLS = new Set(['http:', 'https:']);

/** Ports that are either not web ports or are commonly internal-only services. */
const BLOCKED_PORTS = new Set([
  22, 23, 25, 53, 110, 135, 137, 138, 139, 143, 389, 445, 465, 587, 636, 993, 995,
  1433, 1521, 2049, 2375, 2376, 3306, 3389, 5432, 5900, 5984, 6379, 9200, 11211, 27017,
]);

/** Hostnames / suffixes that only ever resolve inside a private network. */
const BLOCKED_HOST_PATTERNS = [
  /^localhost$/i,
  /\.localhost$/i,
  /^ip6-\w+$/i,
  /\.local$/i,
  /\.internal$/i,
  /\.intranet$/i,
  /\.lan$/i,
  /\.home$/i,
  /\.corp$/i,
  /\.private$/i,
  /^metadata\./i,
  /^instance-data(\.|$)/i,
];

const resolveAll = (hostname, family) =>
  new Promise((resolve) => {
    dns.resolve(hostname, family === 6 ? 'AAAA' : 'A', (error, addresses) => {
      resolve(error ? [] : addresses);
    });
  });

/**
 * Validate a hostname's *shape* (before any DNS work). Throws on obvious
 * internal names and on blocked IP literals.
 */
export function assertSafeHostname(hostname) {
  const host = String(hostname || '').trim().replace(/^\[|\]$/g, '');
  if (!host) {
    throw new BlockedTargetError('The URL does not contain a hostname.');
  }
  if (net.isIP(host)) {
    const { blocked, reason } = classifyIp(host);
    if (blocked && !privateTargetsAllowed()) {
      throw new BlockedTargetError(`Target IP ${host} is not allowed: ${reason}.`);
    }
    return host;
  }
  if (privateTargetsAllowed()) return host;
  if (!host.includes('.')) {
    throw new BlockedTargetError(
      `"${host}" is not a fully qualified public hostname. Scans are limited to publicly resolvable targets.`,
    );
  }
  for (const pattern of BLOCKED_HOST_PATTERNS) {
    if (pattern.test(host)) {
      throw new BlockedTargetError(
        `Hostname "${host}" points at a local or internal network and cannot be scanned.`,
      );
    }
  }
  return host;
}

/**
 * Full pre-flight validation: protocol, port, hostname and every DNS answer.
 * @param {URL|string} input
 * @returns {Promise<{url: URL, addresses: string[]}>}
 */
export async function assertSafeUrl(input) {
  let url;
  try {
    url = input instanceof URL ? input : new URL(String(input));
  } catch {
    throw new BlockedTargetError(`"${input}" is not a valid URL.`);
  }

  if (!ALLOWED_PROTOCOLS.has(url.protocol)) {
    throw new BlockedTargetError(
      `Protocol "${url.protocol}" is not supported. Use http:// or https://.`,
    );
  }
  if (url.username || url.password) {
    throw new BlockedTargetError('URLs with embedded credentials are not accepted.');
  }

  const port = url.port ? Number(url.port) : url.protocol === 'https:' ? 443 : 80;
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    throw new BlockedTargetError(`Port ${url.port} is not valid.`);
  }
  if (BLOCKED_PORTS.has(port)) {
    throw new BlockedTargetError(
      `Port ${port} is a non-web / internal service port and cannot be scanned.`,
    );
  }

  const hostname = assertSafeHostname(url.hostname);

  if (net.isIP(hostname)) {
    return { url, addresses: [hostname] };
  }

  const [v4, v6] = await Promise.all([resolveAll(hostname, 4), resolveAll(hostname, 6)]);
  const addresses = [...v4, ...v6];
  if (addresses.length === 0 && privateTargetsAllowed()) {
    // A private-network name may only resolve through the OS resolver
    // (/etc/hosts, mDNS), which dns.resolve does not consult.
    return { url, addresses: [] };
  }
  if (addresses.length === 0) {
    throw new BlockedTargetError(
      `Hostname "${hostname}" could not be resolved. The target must be publicly reachable.`,
    );
  }

  if (!privateTargetsAllowed()) {
    for (const address of addresses) {
      const { blocked, reason } = classifyIp(address);
      if (blocked) {
        throw new BlockedTargetError(
          `Hostname "${hostname}" resolves to ${address}, which is not allowed: ${reason}.`,
        );
      }
    }
  }

  return { url, addresses };
}

/**
 * DNS resolver for the HTTP agents. Any address that is not a public unicast
 * address makes the connection fail, so a rebinding attack cannot move the
 * socket to an internal host after validation.
 */
export function safeLookup(hostname, options, callback) {
  const done = typeof options === 'function' ? options : callback;
  const opts = typeof options === 'function' ? {} : options || {};

  dns.lookup(hostname, { ...opts, all: true, verbatim: true }, (error, addresses) => {
    if (error) {
      done(error);
      return;
    }
    const list = Array.isArray(addresses) ? addresses : [addresses];
    const allowed = [];
    for (const entry of list) {
      const { blocked, reason } = classifyIp(entry.address);
      if (blocked && !privateTargetsAllowed()) {
        done(
          new BlockedTargetError(
            `Blocked connection to ${hostname}: resolved address ${entry.address} is ${reason}.`,
          ),
        );
        return;
      }
      allowed.push(entry);
    }
    if (allowed.length === 0) {
      done(new BlockedTargetError(`Hostname ${hostname} did not resolve to any usable address.`));
      return;
    }
    if (opts.all) {
      done(null, allowed);
      return;
    }
    done(null, allowed[0].address, allowed[0].family);
  });
}
