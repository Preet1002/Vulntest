import { severityStyle } from '../../utils/severity.js';

/**
 * Severity badge: a colour swatch *and* the severity word. Severity is never
 * communicated by colour alone anywhere in this dashboard, which is what makes
 * the reserved status palette safe to use on a light surface.
 */
export function SeverityBadge({ severity, size = 'md' }) {
  const style = severityStyle(severity);
  const padding = size === 'sm' ? 'px-1.5 py-0.5 text-[11px]' : 'px-2 py-1 text-xs';

  return (
    <span
      className={`inline-flex items-center gap-1.5 rounded-md font-medium text-ink ring-1 ring-inset ${style.tint} ${style.ring} ${padding}`}
    >
      <span className={`h-2 w-2 shrink-0 rounded-full ${style.dot}`} aria-hidden="true" />
      {severity}
    </span>
  );
}

export function ConfidenceBadge({ confidence }) {
  return (
    <span className="inline-flex items-center rounded-md border border-line px-2 py-1 text-xs text-ink-2">
      {confidence}
    </span>
  );
}

/** Method chip in the endpoint explorer. */
export function MethodBadge({ method }) {
  return (
    <span className="inline-flex min-w-12 justify-center rounded border border-line px-1.5 py-0.5 font-mono text-[11px] text-ink-2">
      {method}
    </span>
  );
}

/** HTTP status chip, coloured by class (a genuine status meaning). */
export function StatusCodeBadge({ code }) {
  const value = Number(code);
  if (!Number.isFinite(value) || value === 0) {
    return <span className="text-xs text-ink-muted">—</span>;
  }

  const tone =
    value < 300
      ? 'text-good'
      : value < 400
        ? 'text-accent'
        : value < 500
          ? 'text-ink-2'
          : 'text-sev-critical';

  return <span className={`font-mono text-xs tabular-nums ${tone}`}>{value}</span>;
}

const TRIAGE_STYLES = {
  Open: 'border-line text-ink-2',
  Confirmed: 'border-sev-critical/40 text-ink',
  'False positive': 'border-line text-ink-muted line-through',
  Fixed: 'border-good/40 text-ink',
};

export function TriageBadge({ status = 'Open' }) {
  return (
    <span className={`inline-flex rounded-md border px-2 py-1 text-xs ${TRIAGE_STYLES[status] || TRIAGE_STYLES.Open}`}>
      {status}
    </span>
  );
}
