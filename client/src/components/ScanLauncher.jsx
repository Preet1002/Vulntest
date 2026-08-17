import { Button } from './ui/Button.jsx';

/**
 * Target entry and scan controls.
 *
 * The authorization checkbox is not decoration: the API rejects any scan whose
 * request does not carry an explicit confirmation, so this is the point where
 * the operator takes responsibility for the target.
 */
export function ScanLauncher({
  target,
  onTargetChange,
  authorized,
  onAuthorizedChange,
  onStart,
  onStop,
  onOpenConfig,
  running,
  busy,
  error,
  config,
}) {
  const canStart = target.trim() !== '' && authorized && !running && !busy;

  const submit = (event) => {
    event.preventDefault();
    if (canStart) onStart();
  };

  return (
    <form onSubmit={submit} className="rounded-xl border border-line bg-surface-1 p-5">
      <div className="flex flex-col gap-3 lg:flex-row lg:items-end">
        <div className="flex-1">
          <label htmlFor="target" className="mb-1.5 block text-xs font-medium text-ink-2">
            Target URL
          </label>
          <input
            id="target"
            name="target"
            type="text"
            inputMode="url"
            autoComplete="off"
            spellCheck="false"
            placeholder="https://example.com"
            value={target}
            onChange={(event) => onTargetChange(event.target.value)}
            disabled={running}
            className="w-full rounded-lg border border-line bg-surface-1 px-3 py-2 font-mono text-sm text-ink placeholder:text-ink-muted disabled:opacity-60"
          />
        </div>

        <div className="flex items-center gap-2">
          {running ? (
            <Button variant="danger" onClick={onStop} disabled={busy}>
              Stop scan
            </Button>
          ) : (
            <Button type="submit" disabled={!canStart}>
              {busy ? 'Starting…' : 'Start scan'}
            </Button>
          )}
          <Button variant="outline" onClick={onOpenConfig} disabled={running}>
            <svg viewBox="0 0 24 24" className="h-4 w-4" fill="none" stroke="currentColor" strokeWidth="1.8">
              <circle cx="12" cy="12" r="3" />
              <path d="M12 3v2m0 14v2M3 12h2m14 0h2M5.6 5.6l1.4 1.4m10 10 1.4 1.4m0-12.8-1.4 1.4m-10 10-1.4 1.4" strokeLinecap="round" />
            </svg>
            Configuration
          </Button>
        </div>
      </div>

      <label className="mt-3 flex cursor-pointer items-start gap-2.5 text-xs text-ink-2">
        <input
          type="checkbox"
          checked={authorized}
          onChange={(event) => onAuthorizedChange(event.target.checked)}
          disabled={running}
          className="mt-0.5 h-4 w-4 shrink-0 accent-[var(--color-accent)]"
        />
        <span>
          I own this target or have written permission to test it, and I accept responsibility for the traffic this
          scan generates. Scans are paced and read-only, but they are still traffic against someone&apos;s
          infrastructure.
        </span>
      </label>

      <p className="mt-2.5 text-[11px] text-ink-muted">
        {config.maxPages} pages max · depth {config.maxDepth} · concurrency {config.concurrency} ·{' '}
        {config.delayMs}ms between requests ·{' '}
        {[
          config.checks.xss && 'XSS',
          config.checks.sqli && 'SQLi',
          config.checks.pathTraversal && 'path traversal',
          config.checks.passive && 'passive',
        ]
          .filter(Boolean)
          .join(', ') || 'no checks enabled'}
      </p>

      {error ? (
        <p role="alert" className="mt-3 rounded-lg border border-sev-critical/30 bg-sev-critical/10 px-3 py-2 text-xs text-ink">
          {error}
        </p>
      ) : null}
    </form>
  );
}
