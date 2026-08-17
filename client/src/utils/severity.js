/**
 * Severity presentation.
 *
 * The colours are the reserved status palette. Two of them fall below 3:1 on
 * the light surface by design, so severity is never encoded by colour alone -
 * every badge, axis tick and chart label carries the severity word next to the
 * swatch, and the findings table is the table view of the severity chart.
 */
export const SEVERITY_ORDER = ['Critical', 'High', 'Medium', 'Low', 'Info'];

export const CONFIDENCE_ORDER = ['High', 'Medium', 'Low'];

/** Tailwind classes per severity. Written out in full so the scanner sees them. */
export const SEVERITY_STYLES = {
  Critical: { dot: 'bg-sev-critical', tint: 'bg-sev-critical/10', ring: 'ring-sev-critical/30' },
  High: { dot: 'bg-sev-high', tint: 'bg-sev-high/10', ring: 'ring-sev-high/30' },
  Medium: { dot: 'bg-sev-medium', tint: 'bg-sev-medium/10', ring: 'ring-sev-medium/30' },
  Low: { dot: 'bg-sev-low', tint: 'bg-sev-low/10', ring: 'ring-sev-low/30' },
  Info: { dot: 'bg-sev-info', tint: 'bg-sev-info/10', ring: 'ring-sev-info/30' },
};

export const severityStyle = (severity) => SEVERITY_STYLES[severity] || SEVERITY_STYLES.Info;

export const severityRank = (severity) => {
  const index = SEVERITY_ORDER.indexOf(severity);
  return index === -1 ? SEVERITY_ORDER.length : index;
};

/** Sort findings by severity, then confidence, then type. */
export function sortFindings(findings) {
  return [...findings].sort((a, b) => {
    const bySeverity = severityRank(a.severity) - severityRank(b.severity);
    if (bySeverity !== 0) return bySeverity;
    const byConfidence = CONFIDENCE_ORDER.indexOf(a.confidence) - CONFIDENCE_ORDER.indexOf(b.confidence);
    if (byConfidence !== 0) return byConfidence;
    return a.type.localeCompare(b.type);
  });
}

/** Counts per severity, always including every level so charts keep a stable shape. */
export function countBySeverity(findings = []) {
  const counts = Object.fromEntries(SEVERITY_ORDER.map((severity) => [severity, 0]));
  for (const finding of findings) {
    if (counts[finding.severity] !== undefined) counts[finding.severity] += 1;
  }
  return counts;
}

export function countByType(findings = []) {
  const counts = new Map();
  for (const finding of findings) {
    counts.set(finding.type, (counts.get(finding.type) || 0) + 1);
  }
  return [...counts.entries()]
    .map(([type, count]) => ({ type, count }))
    .sort((a, b) => b.count - a.count);
}

/** HTTP status classes, used by the endpoint status chart. */
export const STATUS_CLASSES = [
  { key: '2xx', label: '2xx Success', test: (code) => code >= 200 && code < 300 },
  { key: '3xx', label: '3xx Redirect', test: (code) => code >= 300 && code < 400 },
  { key: '4xx', label: '4xx Client error', test: (code) => code >= 400 && code < 500 },
  { key: '5xx', label: '5xx Server error', test: (code) => code >= 500 },
];

export function countByStatusClass(endpoints = []) {
  const counts = Object.fromEntries(STATUS_CLASSES.map(({ key }) => [key, 0]));
  let unknown = 0;

  for (const endpoint of endpoints) {
    const code = Number(endpoint.statusCode);
    if (!Number.isFinite(code) || code === 0) {
      unknown += 1;
      continue;
    }
    const bucket = STATUS_CLASSES.find(({ test }) => test(code));
    if (bucket) counts[bucket.key] += 1;
    else unknown += 1;
  }

  const rows = STATUS_CLASSES.map(({ key, label }) => ({ key, label, count: counts[key] }));
  if (unknown > 0) rows.push({ key: 'n/a', label: 'Not requested', count: unknown });
  return rows;
}
