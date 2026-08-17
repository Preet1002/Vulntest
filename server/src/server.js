import { createApp } from './app.js';
import { SERVER_CONFIG } from './config/index.js';
import { logger } from './utils/logger.js';

const app = createApp();

const server = app.listen(SERVER_CONFIG.port, SERVER_CONFIG.host, () => {
  logger.info('scanner API listening', {
    url: `http://${SERVER_CONFIG.host}:${SERVER_CONFIG.port}`,
    allowedOrigins: SERVER_CONFIG.corsOrigins,
  });

  if (SERVER_CONFIG.allowPrivateTargets) {
    logger.warn(
      'ALLOW_PRIVATE_TARGETS is enabled: localhost and private network targets can be scanned. ' +
        'Use this only on a workstation for your own local or staging apps - never on a shared or public deployment.',
    );
  }
});

// SSE connections are long-lived; give them room but never leak sockets.
server.headersTimeout = 65_000;
server.requestTimeout = 0;

const shutdown = (signal) => {
  logger.info('shutting down', { signal });
  server.close(() => process.exit(0));
  setTimeout(() => process.exit(1), 5_000).unref();
};

process.on('SIGINT', () => shutdown('SIGINT'));
process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('unhandledRejection', (reason) => {
  logger.error('unhandled rejection', { reason: reason?.message || String(reason) });
});
