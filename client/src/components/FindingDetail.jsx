import { useEffect } from 'react';
import { SeverityBadge, ConfidenceBadge } from './ui/Badge.jsx';
import { Button } from './ui/Button.jsx';
import { TRIAGE_OPTIONS } from './FindingsTable.jsx';
import { formatDateTime } from '../utils/format.js';

function Field({ label, children, mono = false }) {
  return (
    <div>
      <p className="text-[11px] font-medium uppercase tracking-wide text-ink-muted">{label}</p>
      <div className={`mt-1 text-sm text-ink break-anywhere ${mono ? 'font-mono text-xs' : ''}`}>{children}</div>
    </div>
  );
}

/** Slide-over with the full evidence for one finding. */
export function FindingDetail({ finding, onClose, onStatusChange }) {
  useEffect(() => {
    if (!finding) return undefined;
    const onKeyDown = (event) => {
      if (event.key === 'Escape') onClose();
    };
    window.addEventListener('keydown', onKeyDown);
    return () => window.removeEventListener('keydown', onKeyDown);
  }, [finding, onClose]);

  if (!finding) return null;

  return (
    <div className="fixed inset-0 z-40 flex justify-end">
      <div className="flex-1 bg-black/30" onClick={onClose} aria-hidden="true" />
      <aside
        role="dialog"
        aria-modal="true"
        aria-labelledby="finding-title"
        className="flex h-full w-full max-w-xl flex-col overflow-y-auto border-l border-line bg-surface-1 shadow-xl"
      >
        <div className="sticky top-0 z-10 flex items-start justify-between gap-4 border-b border-line bg-surface-1 px-5 py-4">
          <div>
            <div className="mb-2 flex flex-wrap items-center gap-2">
              <SeverityBadge severity={finding.severity} />
              <ConfidenceBadge confidence={`${finding.confidence} confidence`} />
            </div>
            <h2 id="finding-title" className="text-base font-semibold text-ink">
              {finding.type}
            </h2>
          </div>
          <Button variant="ghost" size="sm" onClick={onClose} aria-label="Close finding details">
            ✕
          </Button>
        </div>

        <div className="space-y-5 px-5 py-5">
          <Field label="Affected endpoint" mono>
            <a
              href={finding.url}
              target="_blank"
              rel="noreferrer noopener"
              className="text-accent underline underline-offset-2"
            >
              {finding.method} {finding.url}
            </a>
          </Field>

          {finding.parameter ? (
            <Field label="Parameter" mono>
              {finding.parameter}
            </Field>
          ) : null}

          <Field label="Explanation">
            <p className="leading-relaxed text-ink-2">{finding.description}</p>
          </Field>

          <Field label="Evidence">
            <pre className="overflow-x-auto whitespace-pre-wrap rounded-lg bg-surface-2 p-3 font-mono text-[11px] leading-relaxed text-ink-2">
              {finding.evidence || '—'}
            </pre>
          </Field>

          <Field label="Remediation">
            <p className="leading-relaxed text-ink-2">{finding.recommendation}</p>
          </Field>

          {finding.references?.length ? (
            <Field label="References">
              <ul className="space-y-1 text-xs text-ink-2">
                {finding.references.map((reference) => (
                  <li key={reference}>
                    {reference.startsWith('http') ? (
                      <a
                        href={reference}
                        target="_blank"
                        rel="noreferrer noopener"
                        className="text-accent underline underline-offset-2"
                      >
                        {reference}
                      </a>
                    ) : (
                      reference
                    )}
                  </li>
                ))}
              </ul>
            </Field>
          ) : null}

          <Field label="Detected">{formatDateTime(finding.timestamp)}</Field>

          <div>
            <p className="text-[11px] font-medium uppercase tracking-wide text-ink-muted">Triage status</p>
            <div className="mt-2 flex flex-wrap gap-2">
              {TRIAGE_OPTIONS.map((option) => {
                const active = (finding.status || 'Open') === option;
                return (
                  <button
                    key={option}
                    type="button"
                    onClick={() => onStatusChange(finding.id, option)}
                    aria-pressed={active}
                    className={`rounded-lg border px-2.5 py-1.5 text-xs transition-colors ${
                      active ? 'border-accent bg-accent/10 text-ink' : 'border-line text-ink-2 hover:bg-surface-2'
                    }`}
                  >
                    {option}
                  </button>
                );
              })}
            </div>
            <p className="mt-2 text-[11px] text-ink-muted">
              Triage is stored with the scan in this browser. Every finding here is evidence of a *potential* issue -
              confirm it manually before reporting it as a vulnerability.
            </p>
          </div>
        </div>
      </aside>
    </div>
  );
}
