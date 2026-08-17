import { Card, CardHeader } from './ui/Card.jsx';
import { ActivityLog } from './ActivityLog.jsx';
import { formatDuration, formatNumber, truncate } from '../utils/format.js';

const PHASE_LABELS = {
  queued: 'Queued',
  robots: 'Reading robots.txt',
  crawling: 'Crawling',
  'analyzing-scripts': 'Analyzing scripts',
  'probing-endpoints': 'Verifying endpoints',
  testing: 'Testing parameters',
  completed: 'Completed',
  stopped: 'Stopped',
  failed: 'Failed',
};

const STATUS_TONE = {
  completed: 'text-good',
  failed: 'text-sev-critical',
  stopped: 'text-ink-2',
};

function Stat({ label, value }) {
  return (
    <div>
      <dt className="text-[11px] text-ink-muted">{label}</dt>
      <dd className="mt-0.5 text-sm font-medium tabular-nums text-ink">{value}</dd>
    </div>
  );
}

export function ProgressPanel({ scan, connected, streamError }) {
  const statistics = scan.statistics || {};
  const running = !['completed', 'stopped', 'failed'].includes(scan.status);
  const elapsed = scan.completedAt
    ? new Date(scan.completedAt) - new Date(scan.startedAt)
    : Date.now() - new Date(scan.startedAt);

  return (
    <Card>
      <CardHeader
        title="Scan progress"
        subtitle={scan.target}
        actions={
          <span className="flex items-center gap-1.5 text-xs text-ink-muted">
            <span
              className={`h-2 w-2 rounded-full ${
                running ? (connected ? 'bg-good' : 'bg-sev-medium') : 'bg-ink-muted'
              }`}
              aria-hidden="true"
            />
            {running ? (connected ? 'Live' : 'Reconnecting') : 'Finished'}
          </span>
        }
      />

      <div className="mb-4">
        <div className="mb-1.5 flex items-baseline justify-between gap-3">
          <p className={`text-sm font-medium ${STATUS_TONE[scan.status] || 'text-ink'}`}>
            {PHASE_LABELS[scan.phase] || PHASE_LABELS[scan.status] || scan.status}
          </p>
          <p className="text-sm tabular-nums text-ink-2">{scan.progress ?? 0}%</p>
        </div>
        <div
          className="h-2 w-full overflow-hidden rounded-full bg-surface-2"
          role="progressbar"
          aria-valuenow={scan.progress ?? 0}
          aria-valuemin={0}
          aria-valuemax={100}
          aria-label="Scan progress"
        >
          <div
            className={`h-full rounded-full transition-[width] duration-500 ${
              scan.status === 'failed' ? 'bg-sev-critical' : 'bg-accent'
            }`}
            style={{ width: `${Math.max(2, scan.progress ?? 0)}%` }}
          />
        </div>
        <p className="mt-2 truncate font-mono text-[11px] text-ink-muted" title={scan.currentUrl || ''}>
          {scan.currentUrl ? truncate(scan.currentUrl, 96) : running ? 'Waiting for the next request…' : '—'}
        </p>
      </div>

      <dl className="grid grid-cols-2 gap-3 border-t border-line pt-4 sm:grid-cols-5">
        <Stat label="Pages scanned" value={formatNumber(statistics.pages)} />
        <Stat label="Endpoints" value={formatNumber(statistics.endpoints)} />
        <Stat label="Requests" value={formatNumber(statistics.requests)} />
        <Stat label="Errors" value={formatNumber(statistics.errors)} />
        <Stat label="Elapsed" value={formatDuration(elapsed)} />
      </dl>

      {scan.error ? (
        <p className="mt-4 rounded-lg border border-sev-critical/30 bg-sev-critical/10 px-3 py-2 text-xs text-ink">
          {scan.error}
        </p>
      ) : null}
      {streamError ? <p className="mt-3 text-xs text-ink-muted">{streamError}</p> : null}

      <ActivityLog entries={scan.log} />
    </Card>
  );
}
