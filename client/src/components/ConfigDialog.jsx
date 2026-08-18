import { useEffect, useState } from 'react';
import { Button } from './ui/Button.jsx';

const NUMBER_FIELDS = [
  { key: 'maxPages', label: 'Maximum pages', hint: 'Pages fetched before crawling stops.', min: 1, limitKey: 'maxPages' },
  { key: 'maxDepth', label: 'Maximum depth', hint: 'Link hops from the start URL.', min: 0, limitKey: 'maxDepth' },
  { key: 'concurrency', label: 'Concurrency', hint: 'Requests in flight at once.', min: 1, limitKey: 'concurrency' },
  { key: 'delayMs', label: 'Delay between requests (ms)', hint: 'Raised automatically if robots.txt asks.', min: 0, limitKey: 'delayMs' },
  { key: 'requestTimeoutMs', label: 'Request timeout (ms)', min: 1000, limitKey: 'requestTimeoutMs' },
  { key: 'maxRequests', label: 'Request budget', hint: 'Hard cap on total requests.', min: 1, limitKey: 'maxRequests' },
  {
    key: 'maxVariantsPerSignature',
    label: 'Variants per endpoint',
    hint: 'How many value-variants of the same path+parameters to crawl.',
    min: 1,
    limitKey: 'maxVariantsPerSignature',
  },
];

const CHECKS = [
  { key: 'xss', label: 'Reflected XSS', hint: 'Canary reflection and output-encoding analysis.' },
  { key: 'sqli', label: 'SQL injection', hint: 'Error and boolean comparison, read-only.' },
  { key: 'pathTraversal', label: 'Path traversal', hint: 'Non-existent paths only; no OS files requested.' },
  { key: 'passive', label: 'Passive checks', hint: 'Headers, cookies, error disclosure. No extra requests.' },
];

/** Scan configuration modal. Values are clamped again by the API. */
export function ConfigDialog({ open, config, limits, onSave, onClose }) {
  const [draft, setDraft] = useState(config);

  useEffect(() => {
    if (open) setDraft(config);
  }, [open, config]);

  useEffect(() => {
    if (!open) return undefined;
    const onKeyDown = (event) => {
      if (event.key === 'Escape') onClose();
    };
    window.addEventListener('keydown', onKeyDown);
    return () => window.removeEventListener('keydown', onKeyDown);
  }, [open, onClose]);

  if (!open) return null;

  const setNumber = (key, value) => setDraft((previous) => ({ ...previous, [key]: Number(value) }));
  const setFlag = (key, value) => setDraft((previous) => ({ ...previous, [key]: value }));
  const setCheck = (key, value) =>
    setDraft((previous) => ({ ...previous, checks: { ...previous.checks, [key]: value } }));

  const durationMinutes = Math.round((draft.maxScanDurationMs || 0) / 60_000);

  return (
    <div className="fixed inset-0 z-50 flex items-start justify-center overflow-y-auto bg-black/40 p-4 sm:p-8">
      <div
        role="dialog"
        aria-modal="true"
        aria-labelledby="config-title"
        className="w-full max-w-2xl rounded-xl border border-line bg-surface-1 shadow-xl"
      >
        <div className="flex items-center justify-between border-b border-line px-5 py-4">
          <div>
            <h2 id="config-title" className="text-sm font-semibold text-ink">
              Scan configuration
            </h2>
            <p className="mt-0.5 text-xs text-ink-muted">
              The server clamps every value to its own hard limits, shown as the maximum here.
            </p>
          </div>
          <Button variant="ghost" size="sm" onClick={onClose} aria-label="Close configuration">
            ✕
          </Button>
        </div>

        <div className="max-h-[65vh] space-y-6 overflow-y-auto px-5 py-5">
          <div className="grid gap-4 sm:grid-cols-2">
            {NUMBER_FIELDS.map((field) => (
              <div key={field.key}>
                <label htmlFor={field.key} className="mb-1 block text-xs font-medium text-ink-2">
                  {field.label}
                  <span className="ml-1 font-normal text-ink-muted">(max {limits[field.limitKey]})</span>
                </label>
                <input
                  id={field.key}
                  type="number"
                  min={field.min}
                  max={limits[field.limitKey]}
                  value={draft[field.key]}
                  onChange={(event) => setNumber(field.key, event.target.value)}
                  className="w-full rounded-lg border border-line bg-surface-1 px-3 py-2 text-sm tabular-nums text-ink"
                />
                {field.hint ? <p className="mt-1 text-[11px] text-ink-muted">{field.hint}</p> : null}
              </div>
            ))}

            <div>
              <label htmlFor="duration" className="mb-1 block text-xs font-medium text-ink-2">
                Maximum scan duration (minutes)
                <span className="ml-1 font-normal text-ink-muted">
                  (max {Math.round(limits.maxScanDurationMs / 60_000)})
                </span>
              </label>
              <input
                id="duration"
                type="number"
                min={1}
                max={Math.round(limits.maxScanDurationMs / 60_000)}
                value={durationMinutes}
                onChange={(event) => setNumber('maxScanDurationMs', Number(event.target.value) * 60_000)}
                className="w-full rounded-lg border border-line bg-surface-1 px-3 py-2 text-sm tabular-nums text-ink"
              />
            </div>
          </div>

          <fieldset>
            <legend className="mb-2 text-xs font-medium text-ink-2">Detection modules</legend>
            <div className="grid gap-2 sm:grid-cols-2">
              {CHECKS.map((check) => (
                <label
                  key={check.key}
                  className="flex cursor-pointer items-start gap-2.5 rounded-lg border border-line px-3 py-2.5"
                >
                  <input
                    type="checkbox"
                    checked={draft.checks[check.key]}
                    onChange={(event) => setCheck(check.key, event.target.checked)}
                    className="mt-0.5 h-4 w-4 accent-[var(--color-accent)]"
                  />
                  <span>
                    <span className="block text-xs font-medium text-ink">{check.label}</span>
                    <span className="block text-[11px] text-ink-muted">{check.hint}</span>
                  </span>
                </label>
              ))}
            </div>
          </fieldset>

          <fieldset>
            <legend className="mb-2 text-xs font-medium text-ink-2">Scope and etiquette</legend>
            <div className="space-y-2">
              {[
                {
                  key: 'useSitemap',
                  label: 'Use sitemaps',
                  hint: 'Seed the crawl from sitemap.xml. Reaches pages the front page never links to.',
                },
                {
                  key: 'followHostRedirect',
                  label: 'Follow the start URL to where it redirects',
                  hint: 'Handles the usual apex to www hop. Only ever follows within the same site.',
                },
                {
                  key: 'respectRobots',
                  label: 'Respect robots.txt',
                  hint: 'Skip disallowed paths and honour Crawl-delay. Turning this off finds more.',
                },
                {
                  key: 'allowSubdomains',
                  label: 'Include subdomains',
                  hint: 'Only enable when your authorization covers them.',
                },
                {
                  key: 'testForms',
                  label: 'Test form inputs',
                  hint: 'GET forms only, and never forms with a password field.',
                },
                {
                  key: 'testPostForms',
                  label: 'Submit POST forms',
                  hint: 'Off by default: POST submissions can create data on the target.',
                },
              ].map((option) => (
                <label key={option.key} className="flex cursor-pointer items-start gap-2.5">
                  <input
                    type="checkbox"
                    checked={Boolean(draft[option.key])}
                    onChange={(event) => setFlag(option.key, event.target.checked)}
                    className="mt-0.5 h-4 w-4 accent-[var(--color-accent)]"
                  />
                  <span>
                    <span className="block text-xs font-medium text-ink">{option.label}</span>
                    <span className="block text-[11px] text-ink-muted">{option.hint}</span>
                  </span>
                </label>
              ))}
            </div>
          </fieldset>
        </div>

        <div className="flex justify-end gap-2 border-t border-line px-5 py-4">
          <Button variant="outline" onClick={onClose}>
            Cancel
          </Button>
          <Button onClick={() => onSave(draft)}>Save configuration</Button>
        </div>
      </div>
    </div>
  );
}
