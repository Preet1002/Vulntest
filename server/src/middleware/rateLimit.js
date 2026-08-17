/**
 * API-side rate limiting. This protects the scanner's own API - the pacing of
 * outbound requests to a target is handled separately in services/rateLimiter.js.
 */
import rateLimit from 'express-rate-limit';
import { SERVER_CONFIG } from '../config/index.js';

const message = (text) => ({ error: { code: 'rate_limited', message: text } });

/** Broad limit for reads (status polling, findings, endpoints). */
export const apiLimiter = rateLimit({
  windowMs: 60_000,
  limit: SERVER_CONFIG.apiRateLimit,
  standardHeaders: 'draft-7',
  legacyHeaders: false,
  message: message('Too many API requests. Slow down and try again shortly.'),
});

/** Starting a scan is expensive, so it is limited much more tightly. */
export const scanLimiter = rateLimit({
  windowMs: 5 * 60_000,
  limit: SERVER_CONFIG.scanRateLimit,
  standardHeaders: 'draft-7',
  legacyHeaders: false,
  message: message('Too many scans started from this address. Wait a few minutes before starting another.'),
});
