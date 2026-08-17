import { useState } from 'react';
import { SummaryCards } from './SummaryCards.jsx';
import { FindingsTable } from './FindingsTable.jsx';
import { FindingDetail } from './FindingDetail.jsx';
import { EndpointExplorer } from './EndpointExplorer.jsx';
import { SeverityChart } from './charts/SeverityChart.jsx';
import { TypeChart } from './charts/TypeChart.jsx';
import { StatusCodeChart } from './charts/StatusCodeChart.jsx';

/**
 * The results view, shared by the live dashboard and by any stored scan opened
 * from history - so a saved scan renders exactly like the one you just ran.
 */
export function ScanResults({ scan, onFindingStatusChange }) {
  const [selected, setSelected] = useState(null);
  const findings = scan.findings || [];
  const endpoints = scan.endpoints || [];

  const changeStatus = (findingId, status) => {
    onFindingStatusChange?.(findingId, status);
    setSelected((previous) => (previous && previous.id === findingId ? { ...previous, status } : previous));
  };

  return (
    <div className="space-y-4">
      <SummaryCards statistics={scan.statistics || {}} findings={findings} />

      <div className="grid gap-4 lg:grid-cols-3">
        <SeverityChart findings={findings} />
        <TypeChart findings={findings} />
        <StatusCodeChart endpoints={endpoints} />
      </div>

      <FindingsTable findings={findings} selectedId={selected?.id} onSelect={setSelected} />

      <EndpointExplorer endpoints={endpoints} />

      <FindingDetail
        finding={selected ? findings.find((finding) => finding.id === selected.id) || selected : null}
        onClose={() => setSelected(null)}
        onStatusChange={changeStatus}
      />
    </div>
  );
}
