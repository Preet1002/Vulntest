/**
 * Per-scan pacing: a concurrency semaphore combined with a minimum delay
 * between request starts. Every outbound request goes through `schedule()`,
 * so a scan can never burst against the target.
 */
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

export class RateLimiter {
  /**
   * @param {{concurrency?: number, delayMs?: number}} options
   */
  constructor({ concurrency = 2, delayMs = 250 } = {}) {
    this.concurrency = Math.max(1, concurrency);
    this.delayMs = Math.max(0, delayMs);
    this.active = 0;
    this.queue = [];
    this.lastStart = 0;
  }

  /** Raise the delay (used when robots.txt asks for a slower crawl). */
  setMinimumDelay(ms) {
    if (Number.isFinite(ms) && ms > this.delayMs) this.delayMs = ms;
  }

  #next() {
    if (this.queue.length === 0 || this.active >= this.concurrency) return;
    const resolve = this.queue.shift();
    this.active += 1;
    resolve();
  }

  async #acquire() {
    if (this.active < this.concurrency) {
      this.active += 1;
    } else {
      await new Promise((resolve) => this.queue.push(resolve));
    }

    const now = Date.now();
    const wait = this.lastStart + this.delayMs - now;
    if (wait > 0) await sleep(wait);
    this.lastStart = Date.now();
  }

  #release() {
    this.active -= 1;
    this.#next();
  }

  /**
   * Run `task` once a slot is free and the inter-request delay has elapsed.
   * @template T
   * @param {() => Promise<T>} task
   * @returns {Promise<T>}
   */
  async schedule(task) {
    await this.#acquire();
    try {
      return await task();
    } finally {
      this.#release();
    }
  }
}

/** Run `tasks` with at most `limit` running at a time, preserving result order. */
export async function pooled(items, limit, worker) {
  const results = new Array(items.length);
  let cursor = 0;

  const runners = new Array(Math.max(1, Math.min(limit, items.length))).fill(null).map(async () => {
    while (cursor < items.length) {
      const index = cursor;
      cursor += 1;
      results[index] = await worker(items[index], index);
    }
  });

  await Promise.all(runners);
  return results;
}
