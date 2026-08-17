import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import { SERVER_CONFIG } from './config/index.js';
import { scansRouter, metaRouter } from './routes/scans.js';
import { apiLimiter } from './middleware/rateLimit.js';
import { errorHandler, notFound } from './middleware/errorHandler.js';
import { AppError } from './utils/errors.js';

export function createApp() {
  const app = express();

  // The API is JSON-only and never renders HTML, so CSP can be maximally strict.
  app.use(
    helmet({
      contentSecurityPolicy: {
        directives: { defaultSrc: ["'none'"], frameAncestors: ["'none'"] },
      },
      crossOriginResourcePolicy: { policy: 'same-site' },
    }),
  );

  app.use(
    cors({
      origin(origin, callback) {
        // Same-origin / curl requests have no Origin header.
        if (!origin || SERVER_CONFIG.corsOrigins.includes(origin)) {
          callback(null, true);
          return;
        }
        callback(new AppError(`Origin ${origin} is not allowed to use this API.`, { status: 403, code: 'cors_denied' }));
      },
      methods: ['GET', 'POST'],
      maxAge: 600,
    }),
  );

  app.use(express.json({ limit: '32kb' }));
  app.disable('x-powered-by');
  // Rate limiters key on the client address; trust only a local reverse proxy.
  app.set('trust proxy', 'loopback');

  app.get('/api/health', (_req, res) => {
    res.json({ status: 'ok', uptimeSeconds: Math.round(process.uptime()) });
  });

  app.use('/api', apiLimiter, metaRouter);
  app.use('/api/scans', apiLimiter, scansRouter);

  app.use(notFound);
  app.use(errorHandler);

  return app;
}
