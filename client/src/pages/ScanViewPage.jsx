import { useCallback, useEffect, useState } from 'react';
import { Link, useNavigate, useParams } from 'react-router-dom';
import { ScanResults } from '../components/ScanResults.jsx';
import { Card } from '../components/ui/Card.jsx';
import { Button } from '../components/ui/Button.jsx';
import { EmptyState } from '../components/ui/EmptyState.jsx';
import { loadScan, updateFindingStatus, deleteScan } from '../utils/storage.js';
import { getScan } from '../services/api.js';
import { formatDateTime, formatDuration } from '../utils/format.js';

/** A stored scan, reopened from history (or from the server if still cached). */
export function ScanViewPage() {
  const { id } = useParams();
  const navigate = useNavigate();
  const [scan, setScan] = useState(() => loadScan(id));
  const [loading, setLoading] = useState(!scan);

  useEffect(() => {
    const stored = loadScan(id);
    if (stored) {
      setScan(stored);
      setLoading(false);
      return;
    }
    // Not in this browser's history - it may still be in the server's memory.
    setLoading(true);
    getScan(id)
      .then(({ scan: fetched }) => setScan(fetched))
      .catch(() => setScan(null))
      .finally(() => setLoading(false));
  }, [id]);

  const onFindingStatusChange = useCallback(
    (findingId, status) => {
      updateFindingStatus(id, findingId, status);
      setScan((previous) =>
        previous
          ? {
              ...previous,
              findings: previous.findings.map((finding) =>
                finding.id === findingId ? { ...finding, status } : finding,
              ),
            }
          : previous,
      );
    },
    [id],
  );

  const onDelete = () => {
    if (!window.confirm('Delete this scan from history?')) return;
    deleteScan(id);
    navigate('/history');
  };

  if (loading) {
    return (
      <Card>
        <p className="text-sm text-ink-muted">Loading scan…</p>
      </Card>
    );
  }

  if (!scan) {
    return (
      <Card>
        <EmptyState
          title="Scan not found"
          description="This scan is not in this browser's history and is no longer held in the server's memory."
          action={
            <Link to="/history" className="mt-2 text-xs text-accent underline underline-offset-2">
              Back to history
            </Link>
          }
        />
      </Card>
    );
  }

  return (
    <div className="space-y-4">
      <Card>
        <div className="flex flex-wrap items-start justify-between gap-4">
          <div>
            <p className="text-xs text-ink-muted">Saved scan</p>
            <h2 className="mt-0.5 break-anywhere font-mono text-sm text-ink">{scan.target}</h2>
            <p className="mt-1.5 text-xs text-ink-muted">
              {formatDateTime(scan.startedAt)} · {scan.status} ·{' '}
              {formatDuration(scan.statistics?.durationMs || 0)} · {scan.statistics?.requests ?? 0} requests
            </p>
          </div>
          <div className="flex items-center gap-2">
            <Link
              to="/history"
              className="rounded-lg border border-line px-3 py-2 text-sm text-ink-2 hover:bg-surface-2"
            >
              Back
            </Link>
            <Button variant="outline" onClick={onDelete}>
              Delete scan
            </Button>
          </div>
        </div>
      </Card>

      <ScanResults scan={scan} onFindingStatusChange={onFindingStatusChange} />
    </div>
  );
}
