import { useMemo, useState } from 'react';
import { Card, CardHeader } from './ui/Card.jsx';
import { EmptyState } from './ui/EmptyState.jsx';
import { MethodBadge, StatusCodeBadge } from './ui/Badge.jsx';
import { pathOf, truncate } from '../utils/format.js';

const STATUS_FILTERS = ['All', '2xx', '3xx', '4xx', '5xx', 'No response'];

const inStatusClass = (code, filter) => {
  const value = Number(code);
  if (filter === 'No response') return !Number.isFinite(value) || value === 0;
  if (!Number.isFinite(value)) return false;
  const bucket = Math.floor(value / 100);
  return `${bucket}xx` === filter;
};

/** Searchable inventory of everything the crawler discovered. */
export function EndpointExplorer({ endpoints = [] }) {
  const [query, setQuery] = useState('');
  const [method, setMethod] = useState('All');
  const [status, setStatus] = useState('All');
  const [only, setOnly] = useState('All');

  const methods = useMemo(
    () => ['All', ...new Set(endpoints.map((endpoint) => endpoint.method))].sort(),
    [endpoints],
  );

  const visible = useMemo(() => {
    const needle = query.trim().toLowerCase();
    return endpoints.filter((endpoint) => {
      if (method !== 'All' && endpoint.method !== method) return false;
      if (status !== 'All' && !inStatusClass(endpoint.statusCode, status)) return false;
      if (only === 'With parameters' && endpoint.parameters.length === 0) return false;
      if (only === 'With forms' && endpoint.forms.length === 0) return false;
      if (only === 'With findings' && !endpoint.vulnerable) return false;
      if (needle && !endpoint.url.toLowerCase().includes(needle)) return false;
      return true;
    });
  }, [endpoints, query, method, status, only]);

  return (
    <Card padded={false}>
      <div className="px-5 pt-5">
        <CardHeader
          title="Discovered endpoints"
          subtitle={`${visible.length} of ${endpoints.length} endpoint${endpoints.length === 1 ? '' : 's'}`}
        />
        <div className="mb-4 flex flex-wrap items-center gap-2.5">
          <input
            type="search"
            value={query}
            onChange={(event) => setQuery(event.target.value)}
            placeholder="Search URLs"
            aria-label="Search endpoints"
            className="min-w-56 flex-1 rounded-lg border border-line bg-surface-1 px-3 py-1.5 text-xs text-ink placeholder:text-ink-muted"
          />
          {[
            { label: 'Method', value: method, onChange: setMethod, options: methods },
            { label: 'Status', value: status, onChange: setStatus, options: STATUS_FILTERS },
            {
              label: 'Show',
              value: only,
              onChange: setOnly,
              options: ['All', 'With parameters', 'With forms', 'With findings'],
            },
          ].map((filter) => (
            <label key={filter.label} className="flex items-center gap-1.5 text-xs text-ink-muted">
              {filter.label}
              <select
                value={filter.value}
                onChange={(event) => filter.onChange(event.target.value)}
                className="rounded-lg border border-line bg-surface-1 px-2 py-1.5 text-xs text-ink"
              >
                {filter.options.map((option) => (
                  <option key={option} value={option}>
                    {option}
                  </option>
                ))}
              </select>
            </label>
          ))}
        </div>
      </div>

      {visible.length === 0 ? (
        <div className="px-5 pb-5">
          <EmptyState
            title={endpoints.length === 0 ? 'Nothing discovered yet' : 'No endpoints match these filters'}
            description={
              endpoints.length === 0
                ? 'Pages, forms, query parameters and API routes found in JavaScript are listed here as they are discovered.'
                : undefined
            }
          />
        </div>
      ) : (
        <div className="max-h-[520px] overflow-auto">
          <table className="w-full min-w-[860px] text-sm">
            <thead className="sticky top-0 z-10">
              <tr className="border-y border-line bg-surface-2 text-left text-xs text-ink-muted">
                <th scope="col" className="px-5 py-2.5 font-medium">Method</th>
                <th scope="col" className="px-3 py-2.5 font-medium">URL</th>
                <th scope="col" className="px-3 py-2.5 font-medium">Parameters</th>
                <th scope="col" className="px-3 py-2.5 font-medium">Forms</th>
                <th scope="col" className="px-3 py-2.5 font-medium">Source</th>
                <th scope="col" className="px-3 py-2.5 font-medium">Status</th>
                <th scope="col" className="px-5 py-2.5 font-medium">Findings</th>
              </tr>
            </thead>
            <tbody>
              {visible.map((endpoint) => (
                <tr key={endpoint.id} className="border-b border-line/60 last:border-0">
                  <td className="px-5 py-2.5">
                    <MethodBadge method={endpoint.method} />
                  </td>
                  <td className="px-3 py-2.5">
                    <span className="font-mono text-xs text-ink-2" title={endpoint.url}>
                      {truncate(pathOf(endpoint.url), 52)}
                    </span>
                    {endpoint.title ? (
                      <span className="ml-2 text-[11px] text-ink-muted">{truncate(endpoint.title, 28)}</span>
                    ) : null}
                  </td>
                  <td className="px-3 py-2.5">
                    {endpoint.parameters.length === 0 ? (
                      <span className="text-xs text-ink-muted">—</span>
                    ) : (
                      <span className="flex flex-wrap gap-1">
                        {endpoint.parameters.slice(0, 4).map((parameter) => (
                          <span
                            key={parameter}
                            className="rounded border border-line px-1.5 py-0.5 font-mono text-[11px] text-ink-2"
                          >
                            {truncate(parameter, 14)}
                          </span>
                        ))}
                        {endpoint.parameters.length > 4 ? (
                          <span className="text-[11px] text-ink-muted">+{endpoint.parameters.length - 4}</span>
                        ) : null}
                      </span>
                    )}
                  </td>
                  <td className="px-3 py-2.5 text-xs tabular-nums text-ink-2">
                    {endpoint.forms.length || <span className="text-ink-muted">—</span>}
                  </td>
                  <td className="px-3 py-2.5 text-xs text-ink-muted">{endpoint.source}</td>
                  <td className="px-3 py-2.5">
                    <StatusCodeBadge code={endpoint.statusCode} />
                  </td>
                  <td className="px-5 py-2.5">
                    {endpoint.findingCount > 0 ? (
                      <span className="inline-flex items-center gap-1.5 text-xs text-ink">
                        <span className="h-2 w-2 rounded-full bg-sev-high" aria-hidden="true" />
                        {endpoint.findingCount}
                      </span>
                    ) : (
                      <span className="text-xs text-ink-muted">—</span>
                    )}
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
