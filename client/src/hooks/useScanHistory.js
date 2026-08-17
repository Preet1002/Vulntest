/** Scan history backed by localStorage. */
import { useCallback, useState } from 'react';
import {
  clearHistory,
  deleteScan,
  historyBytes,
  loadHistory,
  saveScan,
  updateFindingStatus,
} from '../utils/storage.js';

export function useScanHistory() {
  const [history, setHistory] = useState(() => loadHistory());
  const [quotaWarning, setQuotaWarning] = useState(false);

  const save = useCallback((scan) => {
    const { history: next, saved } = saveScan(scan);
    setHistory(next);
    setQuotaWarning(!saved);
    return saved;
  }, []);

  const remove = useCallback((id) => setHistory(deleteScan(id)), []);

  const clear = useCallback(() => setHistory(clearHistory()), []);

  const reload = useCallback(() => setHistory(loadHistory()), []);

  const setFindingStatus = useCallback((scanId, findingId, status) => {
    setHistory(updateFindingStatus(scanId, findingId, status));
  }, []);

  return {
    history,
    save,
    remove,
    clear,
    reload,
    setFindingStatus,
    quotaWarning,
    bytes: historyBytes(),
  };
}
