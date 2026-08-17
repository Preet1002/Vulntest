import { useMemo, useState } from 'react';
import { Card, CardHeader } from './ui/Card.jsx';
import { EmptyState } from './ui/EmptyState.jsx';
import { SeverityBadge, ConfidenceBadge, TriageBadge } from './ui/Badge.jsx';
import { SEVERITY_ORDER, sortFindings } from '../utils/severity.js';
import { pathOf, truncate } from '../utils/format.js';

const TRIAGE_OPTIONS = ['Open', 'Confirmed', 'False positive', 'Fixed'];

function Select({ label, value, onChange, options }) {
  return (
    <label className="flex items-center gap-1.5 text-xs text-ink-muted">
      {label}
      <select
        value={value}
        onChange={(event) => onChange(event.target.value)}
        className="rounded-lg border border-line bg-surface-1 px-2 py-1.5 text-xs text-ink"
      >
        {options.map((option) => (
          <option key={option} value={option}>
            {option}
          </option>
        ))}
      </select>
    </label>
  );
}

export function FindingsTable({ findings = [], selectedId, onSelect }) {
  const [severity, setSeverity] = useState('All');
  const [type, setType] = useState('All');
  const [confidence, setConfidence] = useState('All');
  const [triage, setTriage] = useState('All');
  const [query, setQuery] = useState('');

  const types = useMemo(
    () => ['All', ...new Set(findings.map((finding) => finding.type))].sort(),
    [findings],
  );

  const visible = useMemo(() => {
    const needle = query.trim().toLowerCase();
    return sortFindings(
      findings.filter((finding) => {
        if (severity !== 'All' && finding.severity !== severity) return false;
        if (type !== 'All' && finding.type !== type) return false;
        if (confidence !== 'All' && finding.confidence !== confidence) return false;
        if (triage !== 'All' && (finding.status || 'Open') !== triage) return false;
        if (needle) {
          const haystack = `${finding.url} ${finding.parameter || ''} ${finding.type}`.toLowerCase();
          if (!haystack.includes(needle)) return false;
        }
        return true;
      }),
    );
  }, [findings, severity, type, confidence, triage, query]);

  return (
    <Card padded={false}>
      <div className="px-5 pt-5">
        <CardHeader
          title="Vulnerabilities"
          subtitle={`${visible.length} of ${findings.length} finding${findings.length === 1 ? '' : 's'}`}
        />
        {/* One filter row above the table it scopes. */}
        <div className="mb-4 flex flex-wrap items-center gap-2.5">
          <input
            type="search"
            value={query}
            onChange={(event) => setQuery(event.target.value)}
            placeholder="Search URL, parameter or type"
            aria-label="Search findings"
            className="min-w-56 flex-1 rounded-lg border border-line bg-surface-1 px-3 py-1.5 text-xs text-ink placeholder:text-ink-muted"
          />
          <Select label="Severity" value={severity} onChange={setSeverity} options={['All', ...SEVERITY_ORDER]} />
          <Select label="Type" value={type} onChange={setType} options={types} />
          <Select label="Confidence" value={confidence} onChange={setConfidence} options={['All', 'High', 'Medium', 'Low']} />
          <Select label="Status" value={triage} onChange={setTriage} options={['All', ...TRIAGE_OPTIONS]} />
        </div>
      </div>

      {visible.length === 0 ? (
        <div className="px-5 pb-5">
          <EmptyState
            title={findings.length === 0 ? 'No findings reported' : 'No findings match these filters'}
            description={
              findings.length === 0
                ? 'Findings appear here as the scanner collects evidence. An empty list is a good result, not a failed scan.'
                : 'Clear or widen the filters to see the rest of the findings.'
            }
          />
        </div>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full min-w-[860px] text-sm">
            <thead>
              <tr className="border-y border-line bg-surface-2/60 text-left text-xs text-ink-muted">
                <th scope="col" className="px-5 py-2.5 font-medium">Severity</th>
                <th scope="col" className="px-3 py-2.5 font-medium">Type</th>
                <th scope="col" className="px-3 py-2.5 font-medium">URL</th>
                <th scope="col" className="px-3 py-2.5 font-medium">Parameter</th>
                <th scope="col" className="px-3 py-2.5 font-medium">Confidence</th>
                <th scope="col" className="px-5 py-2.5 font-medium">Status</th>
              </tr>
            </thead>
            <tbody>
              {visible.map((finding) => (
                <tr
                  key={finding.id}
                  tabIndex={0}
                  role="button"
                  aria-label={`Open details for ${finding.severity} ${finding.type}`}
                  onClick={() => onSelect(finding)}
                  onKeyDown={(event) => {
                    if (event.key === 'Enter' || event.key === ' ') {
                      event.preventDefault();
                      onSelect(finding);
                    }
                  }}
                  className={`cursor-pointer border-b border-line/60 transition-colors last:border-0 hover:bg-surface-2 ${
                    selectedId === finding.id ? 'bg-surface-2' : ''
                  }`}
                >
                  <td className="px-5 py-3">
                    <SeverityBadge severity={finding.severity} size="sm" />
                  </td>
                  <td className="px-3 py-3 text-ink">{finding.type}</td>
                  <td className="px-3 py-3">
                    <span className="font-mono text-xs text-ink-2" title={finding.url}>
                      {truncate(pathOf(finding.url), 46)}
                    </span>
                  </td>
                  <td className="px-3 py-3 font-mono text-xs text-ink-2">{finding.parameter || '—'}</td>
                  <td className="px-3 py-3">
                    <ConfidenceBadge confidence={finding.confidence} />
                  </td>
                  <td className="px-5 py-3">
                    <TriageBadge status={finding.status || 'Open'} />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </Card>
  );
}

export { TRIAGE_OPTIONS };
