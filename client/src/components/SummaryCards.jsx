import { formatNumber } from '../utils/format.js';
import { countBySeverity } from '../utils/severity.js';

/**
 * Stat tiles. Each headline is a single number, so it is a tile rather than a
 * chart; the severity tiles carry a colour swatch beside the label they name.
 */
function Tile({ label, value, hint, swatch }) {
  return (
    <div className="rounded-xl border border-line bg-surface-1 px-4 py-3.5">
      <div className="flex items-center gap-1.5">
        {swatch ? <span className={`h-2 w-2 rounded-full ${swatch}`} aria-hidden="true" /> : null}
        <p className="text-xs font-medium text-ink-muted">{label}</p>
      </div>
      <p className="mt-1.5 text-2xl font-semibold leading-none text-ink">{value}</p>
      {hint ? <p className="mt-1.5 text-[11px] text-ink-muted">{hint}</p> : null}
    </div>
  );
}

export function SummaryCards({ statistics = {}, findings = [] }) {
  const counts = countBySeverity(findings);
  const total = findings.length;

  return (
    <div className="grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-6">
      <Tile label="Pages crawled" value={formatNumber(statistics.pages)} hint={`${formatNumber(statistics.requests)} requests`} />
      <Tile
        label="Endpoints found"
        value={formatNumber(statistics.endpoints)}
        hint={statistics.parametersTested ? `${formatNumber(statistics.parametersTested)} params tested` : undefined}
      />
      <Tile
        label="Vulnerabilities"
        value={formatNumber(total)}
        hint={counts.Critical > 0 ? `${counts.Critical} critical` : `${counts.Info} informational`}
      />
      <Tile label="High" value={formatNumber(counts.High)} swatch="bg-sev-high" />
      <Tile label="Medium" value={formatNumber(counts.Medium)} swatch="bg-sev-medium" />
      <Tile label="Low" value={formatNumber(counts.Low)} swatch="bg-sev-low" />
    </div>
  );
}
