import { HistoryTable } from '../components/HistoryTable.jsx';
import { useScanHistory } from '../hooks/useScanHistory.js';

export function HistoryPage() {
  const { history, remove, clear, bytes } = useScanHistory();

  const onClear = () => {
    if (window.confirm('Delete every stored scan from this browser? This cannot be undone.')) clear();
  };

  const onDelete = (id) => {
    if (window.confirm('Delete this scan from history?')) remove(id);
  };

  return (
    <div className="space-y-4">
      <HistoryTable history={history} onDelete={onDelete} onClear={onClear} bytes={bytes} />
      <p className="px-1 text-xs text-ink-muted">
        History lives only in this browser&apos;s localStorage - it is never uploaded. Clearing site data removes it.
        Scan results can name internal paths and parameters, so treat this browser profile as you would the report
        itself.
      </p>
    </div>
  );
}
