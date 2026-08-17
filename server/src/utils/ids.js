import { randomUUID, randomBytes } from 'node:crypto';

export const scanId = () => `scan_${randomUUID()}`;

export const findingId = () => `finding-${randomBytes(6).toString('hex')}`;

export const endpointId = () => `endpoint-${randomBytes(6).toString('hex')}`;

/**
 * Random token used as a harmless canary in reflection tests.
 * Lowercase alphanumeric so that it survives most encodings and case handling
 * unchanged, which keeps reflection matching reliable.
 */
export const canaryToken = (prefix = 'xss') => `${prefix}${randomBytes(5).toString('hex')}`;
