import { AppError } from '../utils/errors.js';
import { logger } from '../utils/logger.js';

export function notFound(req, res) {
  res.status(404).json({
    error: { code: 'not_found', message: `No route matches ${req.method} ${req.originalUrl}.` },
  });
}

/* eslint-disable-next-line no-unused-vars -- Express identifies error handlers by arity */
export function errorHandler(error, req, res, next) {
  if (error instanceof AppError) {
    res.status(error.status).json({
      error: { code: error.code, message: error.message, details: error.details },
    });
    return;
  }

  if (error?.type === 'entity.too.large') {
    res.status(413).json({ error: { code: 'payload_too_large', message: 'Request body is too large.' } });
    return;
  }
  if (error instanceof SyntaxError && 'body' in error) {
    res.status(400).json({ error: { code: 'invalid_json', message: 'Request body is not valid JSON.' } });
    return;
  }

  logger.error('unhandled error', { message: error?.message, stack: error?.stack });
  // Never leak internals to the client.
  res.status(500).json({
    error: { code: 'internal_error', message: 'An unexpected error occurred while handling the request.' },
  });
}
