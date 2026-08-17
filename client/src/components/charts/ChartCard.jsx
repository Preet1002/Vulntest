import { useId, useState } from 'react';
import { Card, CardHeader } from '../ui/Card.jsx';
import { EmptyState } from '../ui/EmptyState.jsx';

/**
 * Shared frame for every chart.
 *
 * Each chart ships with a table view twin: the same numbers, reachable without
 * relying on colour or on hovering a mark.
 */
export function ChartCard({ title, subtitle, rows = [], valueLabel = 'Count', empty, children }) {
  const [view, setView] = useState('chart');
  const headingId = useId();
  const hasData = rows.some((row) => row.value > 0);

  const toggle = (
    <div className="flex rounded-lg border border-line p-0.5" role="group" aria-label={`${title} view`}>
      {['chart', 'table'].map((option) => (
        <button
          key={option}
          type="button"
          onClick={() => setView(option)}
          aria-pressed={view === option}
          className={`rounded-md px-2 py-1 text-xs capitalize transition-colors ${
            view === option ? 'bg-surface-2 text-ink' : 'text-ink-muted hover:text-ink-2'
          }`}
        >
          {option}
        </button>
      ))}
    </div>
  );

  return (
    <Card>
      <CardHeader id={headingId} title={title} subtitle={subtitle} actions={hasData ? toggle : null} />
      {!hasData ? (
        <EmptyState title={empty?.title || 'Nothing to show yet'} description={empty?.description} />
      ) : view === 'chart' ? (
        <div aria-labelledby={headingId}>{children}</div>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-line text-left text-xs text-ink-muted">
                <th scope="col" className="pb-2 font-medium">
                  Category
                </th>
                <th scope="col" className="pb-2 text-right font-medium">
                  {valueLabel}
                </th>
              </tr>
            </thead>
            <tbody>
              {rows.map((row) => (
                <tr key={row.label} className="border-b border-line/60 last:border-0">
                  <td className="py-2 text-ink-2">{row.label}</td>
                  <td className="py-2 text-right tabular-nums text-ink">{row.value}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </Card>
  );
}

/** Tooltip body shared by the charts, styled from the surface tokens. */
export function ChartTooltip({ active, payload, label, suffix = '' }) {
  if (!active || !payload?.length) return null;
  return (
    <div className="rounded-lg border border-line bg-surface-1 px-3 py-2 text-xs shadow-sm">
      <p className="font-medium text-ink">{label}</p>
      <p className="text-ink-2">
        <span className="tabular-nums">{payload[0].value}</span> {suffix}
      </p>
    </div>
  );
}
