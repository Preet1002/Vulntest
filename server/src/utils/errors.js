/** Application error carrying an HTTP status and a stable machine-readable code. */
export class AppError extends Error {
  constructor(message, { status = 400, code = 'bad_request', details = null } = {}) {
    super(message);
    this.name = 'AppError';
    this.status = status;
    this.code = code;
    this.details = details;
  }
}

/** Raised whenever a URL is rejected by the SSRF / target-scope policy. */
export class BlockedTargetError extends AppError {
  constructor(message, details = null) {
    super(message, { status: 400, code: 'blocked_target', details });
    this.name = 'BlockedTargetError';
  }
}
