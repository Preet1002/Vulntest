/**
 * IP address classification used by the SSRF guard.
 *
 * The scanner must only ever reach public internet hosts. Everything that could
 * point back at the machine running the scanner, at a private network, or at a
 * cloud metadata service is rejected here.
 */
import net from 'node:net';

/** [network, prefix length, human readable reason] */
const V4_BLOCKS = [
  ['0.0.0.0', 8, 'unspecified / this-network range'],
  ['10.0.0.0', 8, 'private network (RFC 1918)'],
  ['100.64.0.0', 10, 'carrier-grade NAT range (RFC 6598)'],
  ['127.0.0.0', 8, 'loopback / localhost'],
  ['169.254.0.0', 16, 'link-local range - includes cloud metadata (169.254.169.254)'],
  ['172.16.0.0', 12, 'private network (RFC 1918)'],
  ['192.0.0.0', 24, 'IETF protocol assignments'],
  ['192.0.2.0', 24, 'documentation range (TEST-NET-1)'],
  ['192.88.99.0', 24, '6to4 relay anycast'],
  ['192.168.0.0', 16, 'private network (RFC 1918)'],
  ['198.18.0.0', 15, 'benchmarking range'],
  ['198.51.100.0', 24, 'documentation range (TEST-NET-2)'],
  ['203.0.113.0', 24, 'documentation range (TEST-NET-3)'],
  ['224.0.0.0', 4, 'multicast range'],
  ['240.0.0.0', 4, 'reserved range'],
];

const V6_BLOCKS = [
  ['::', 128, 'unspecified address'],
  ['::1', 128, 'loopback / localhost'],
  ['100::', 64, 'discard-only range'],
  ['fc00::', 7, 'unique local address - includes cloud metadata (fd00:ec2::254)'],
  ['fe80::', 10, 'link-local range'],
  ['ff00::', 8, 'multicast range'],
  ['2001:db8::', 32, 'documentation range'],
];

function ipv4ToBytes(ip) {
  const parts = ip.split('.');
  if (parts.length !== 4) return null;
  const bytes = new Uint8Array(4);
  for (let i = 0; i < 4; i += 1) {
    if (!/^\d{1,3}$/.test(parts[i])) return null;
    const value = Number(parts[i]);
    if (value > 255) return null;
    bytes[i] = value;
  }
  return bytes;
}

function ipv6ToBytes(ip) {
  let address = ip;
  const zoneIndex = address.indexOf('%');
  if (zoneIndex !== -1) address = address.slice(0, zoneIndex);

  // An IPv6 address may embed a dotted-quad tail (::ffff:127.0.0.1).
  let tail = null;
  const lastColon = address.lastIndexOf(':');
  const suffix = address.slice(lastColon + 1);
  if (suffix.includes('.')) {
    tail = ipv4ToBytes(suffix);
    if (!tail) return null;
    address = address.slice(0, lastColon + 1) + '0:0';
  }

  const halves = address.split('::');
  if (halves.length > 2) return null;

  const parseGroups = (segment) =>
    segment
      .split(':')
      .filter((part) => part !== '')
      .map((part) => (/^[0-9a-fA-F]{1,4}$/.test(part) ? Number.parseInt(part, 16) : null));

  const head = parseGroups(halves[0] ?? '');
  const rear = halves.length === 2 ? parseGroups(halves[1] ?? '') : [];
  if ([...head, ...rear].some((group) => group === null)) return null;

  // A dotted-quad tail was already folded into two zero groups above, so the
  // address is always eight groups wide at this point.
  const missing = 8 - head.length - rear.length;
  if (halves.length === 1 && missing !== 0) return null;
  if (missing < 0) return null;

  const groups = [...head, ...new Array(missing).fill(0), ...rear];
  const bytes = new Uint8Array(16);
  groups.forEach((group, index) => {
    bytes[index * 2] = (group >> 8) & 0xff;
    bytes[index * 2 + 1] = group & 0xff;
  });
  if (tail) bytes.set(tail, 12);
  return bytes;
}

function inBlock(bytes, networkBytes, prefixLength) {
  const fullBytes = Math.floor(prefixLength / 8);
  const remainingBits = prefixLength % 8;
  for (let i = 0; i < fullBytes; i += 1) {
    if (bytes[i] !== networkBytes[i]) return false;
  }
  if (remainingBits === 0) return true;
  const mask = (0xff << (8 - remainingBits)) & 0xff;
  return (bytes[fullBytes] & mask) === (networkBytes[fullBytes] & mask);
}

function classifyV4(bytes) {
  for (const [network, prefix, reason] of V4_BLOCKS) {
    const networkBytes = ipv4ToBytes(network);
    if (networkBytes && inBlock(bytes, networkBytes, prefix)) {
      return { blocked: true, reason };
    }
  }
  return { blocked: false, reason: null };
}

const bytesToV4String = (bytes) => Array.from(bytes).join('.');

/**
 * @param {string} ip
 * @returns {{blocked: boolean, reason: string|null}}
 */
export function classifyIp(ip) {
  const version = net.isIP(ip);
  if (version === 0) {
    return { blocked: true, reason: 'not a valid IP address' };
  }

  if (version === 4) {
    const bytes = ipv4ToBytes(ip);
    if (!bytes) return { blocked: true, reason: 'unparsable IPv4 address' };
    return classifyV4(bytes);
  }

  const bytes = ipv6ToBytes(ip);
  if (!bytes) return { blocked: true, reason: 'unparsable IPv6 address' };

  // IPv4-mapped (::ffff:a.b.c.d) and IPv4-compatible addresses are evaluated
  // against the IPv4 rules - otherwise ::ffff:127.0.0.1 would slip through.
  const firstTenZero = bytes.slice(0, 10).every((byte) => byte === 0);
  if (firstTenZero && bytes[10] === 0xff && bytes[11] === 0xff) {
    const embedded = bytes.slice(12);
    const result = classifyV4(embedded);
    return result.blocked
      ? { blocked: true, reason: `IPv4-mapped address (${bytesToV4String(embedded)}): ${result.reason}` }
      : result;
  }
  if (firstTenZero && bytes[10] === 0 && bytes[11] === 0) {
    return { blocked: true, reason: 'IPv4-compatible IPv6 address (deprecated)' };
  }

  // 6to4 (2002::/16) and NAT64 (64:ff9b::/96) embed an IPv4 address that could
  // point at an internal host.
  if (bytes[0] === 0x20 && bytes[1] === 0x02) {
    const embedded = bytes.slice(2, 6);
    const result = classifyV4(embedded);
    if (result.blocked) {
      return { blocked: true, reason: `6to4 address wrapping ${bytesToV4String(embedded)}: ${result.reason}` };
    }
  }
  if (bytes[0] === 0x00 && bytes[1] === 0x64 && bytes[2] === 0xff && bytes[3] === 0x9b) {
    const embedded = bytes.slice(12);
    const result = classifyV4(embedded);
    if (result.blocked) {
      return { blocked: true, reason: `NAT64 address wrapping ${bytesToV4String(embedded)}: ${result.reason}` };
    }
  }

  for (const [network, prefix, reason] of V6_BLOCKS) {
    const networkBytes = ipv6ToBytes(network);
    if (networkBytes && inBlock(bytes, networkBytes, prefix)) {
      return { blocked: true, reason };
    }
  }

  return { blocked: false, reason: null };
}

export const isPublicIp = (ip) => !classifyIp(ip).blocked;
