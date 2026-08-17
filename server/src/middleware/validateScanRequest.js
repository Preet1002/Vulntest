import { AppError } from '../utils/errors.js';
import { HARD_LIMITS } from '../config/index.js';

/**
 * Whitespace or control characters in a URL mean a paste error or an attempt at
 * request smuggling - either way the value never reaches the network.
 */
function hasUnsafeCharacters(value) {
  for (const char of value) {
    const code = char.codePointAt(0);
    if (code <= 0x20 || code === 0x7f) return true;
  }
  return false;
}

/**
 * Shape-check the POST /api/scans body before anything touches the network.
 * Deep validation of the target itself happens in the SSRF guard.
 */
export function validateScanRequest(req, _res, next) {
  const body = req.body;
  if (!body || typeof body !== 'object' || Array.isArray(body)) {
    next(new AppError('Request body must be a JSON object.', { code: 'invalid_body' }));
    return;
  }

  const { target, config, authorized } = body;

  if (typeof target !== 'string' || target.trim() === '') {
    next(new AppError('A "target" URL string is required.', { code: 'missing_target' }));
    return;
  }
  if (target.length > HARD_LIMITS.maxUrlLength) {
    next(new AppError('The target URL is too long.', { code: 'invalid_target' }));
    return;
  }
  if (hasUnsafeCharacters(target.trim())) {
    next(new AppError('The target URL contains whitespace or control characters.', { code: 'invalid_target' }));
    return;
  }
  if (config !== undefined && (typeof config !== 'object' || config === null || Array.isArray(config))) {
    next(new AppError('"config" must be an object when provided.', { code: 'invalid_config' }));
    return;
  }
  if (authorized !== true) {
    next(
      new AppError(
        'Set "authorized": true to confirm you own this target or have written permission to test it.',
        { status: 403, code: 'authorization_not_confirmed' },
      ),
    );
    return;
  }

  next();
}
