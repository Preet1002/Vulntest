/** Tiny structured logger - keeps server output greppable without a dependency. */
const write = (level, message, meta) => {
  const line = {
    ts: new Date().toISOString(),
    level,
    message,
    ...(meta ? { meta } : {}),
  };
  const target = level === 'error' ? process.stderr : process.stdout;
  target.write(`${JSON.stringify(line)}\n`);
};

export const logger = {
  info: (message, meta) => write('info', message, meta),
  warn: (message, meta) => write('warn', message, meta),
  error: (message, meta) => write('error', message, meta),
  debug: (message, meta) => {
    if (process.env.DEBUG) write('debug', message, meta);
  },
};
