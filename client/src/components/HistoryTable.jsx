import { Link } from 'react-router-dom';
import { Card, CardHeader } from './ui/Card.jsx';
import { EmptyState } from './ui/EmptyState.jsx';
import { Button } from './ui/Button.jsx';
import { formatDateTime, formatNumber, truncate } from '../utils/format.js';
import { countBySeverity } from '../utils/severity.js';

/** Previous scans, read from localStorage. */
export function HistoryTable({ history = [], onDelete, onClear, bytes = 0 }) {
  return (
    <Card padded={false}>
      <div className="px-5 pt-5">
        <CardHeader
          title="Scan history"
          subtitle={`${history.length} scan${history.length === 1 ? '' : 's'} stored in this browser · ${(bytes / 1024).toFixed(0)} KB`}
          actions={
            history.length > 0 ? (
              <Button variant="outline" size="sm" onClick={onClear}>
                Clear history
              </Button>
            ) : null
          }
        />
      </div>

      {history.length === 0 ? (
        <div className="px-5 pb-5">
          <EmptyState
            title="No saved scans"
            description="Completed scans are saved to this browser's localStorage automatically. Nothing is sent anywhere else."
            action={
              <Link to="/" className="mt-2 text-xs text-accent underline underline-offset-2">
                Start a scan
              </Link>
            }
          />
        </div>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full min-w-[900px] text-sm">
            <thead>
              <tr className="border-y border-line bg-surface-2/60 text-left text-xs text-ink-muted">
                <th scope="col" className="px-5 py-2.5 font-medium">Target</th>
                <th scope="col" className="px-3 py-2.5 font-medium">Date</th>
                <th scope="col" className="px-3 py-2.5 text-right font-medium">Pages</th>
                <th scope="col" className="px-3 py-2.5 text-right font-medium">Endpoints</th>
                <th scope="col" className="px-3 py-2.5 text-right font-medium">Vulns</th>
                <th scope="col" className="px-3 py-2.5 text-right font-medium">High</th>
                <th scope="col" className="px-3 py-2.5 text-right font-medium">Medium</th>
                <th scope="col" className="px-3 py-2.5 text-right font-medium">Low</th>
                <th scope="col" className="px-5 py-2.5 font-medium">Actions</th>
              </tr>
            </thead>
            <tbody>
              {history.map((scan) => {
                const counts = countBySeverity(scan.findings || []);
                return (
                  <tr key={scan.id} className="border-b border-line/60 last:border-0 hover:bg-surface-2">
                    <td className="px-5 py-3">
                      <Link to={`/scans/${scan.id}`} className="font-mono text-xs text-accent underline underline-offset-2">
                        {truncate(scan.target, 44)}
                      </Link>
                      <span className="ml-2 text-[11px] text-ink-muted">{scan.status}</span>
                    </td>
                    <td className="px-3 py-3 text-xs text-ink-2">{formatDateTime(scan.startedAt)}</td>
                    <td className="px-3 py-3 text-right tabular-nums text-ink-2">{formatNumber(scan.statistics?.pages)}</td>
                    <td className="px-3 py-3 text-right tabular-nums text-ink-2">{formatNumber(scan.statistics?.endpoints)}</td>
                    <td className="px-3 py-3 text-right tabular-nums text-ink">{formatNumber(scan.findings?.length)}</td>
                    <td className="px-3 py-3 text-right tabular-nums text-ink-2">{counts.High + counts.Critical}</td>
                    <td className="px-3 py-3 text-right tabular-nums text-ink-2">{counts.Medium}</td>
                    <td className="px-3 py-3 text-right tabular-nums text-ink-2">{counts.Low}</td>
                    <td className="px-5 py-3">
                      <div className="flex items-center gap-2">
                        <Link
                          to={`/scans/${scan.id}`}
                          className="rounded-lg border border-line px-2.5 py-1.5 text-xs text-ink-2 hover:bg-surface-2"
                        >
                          Open
                        </Link>
                        <Button variant="ghost" size="sm" onClick={() => onDelete(scan.id)}>
                          Delete
                        </Button>
                      </div>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </Card>
  );
}
