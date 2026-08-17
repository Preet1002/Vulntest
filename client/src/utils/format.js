/** Small formatting helpers shared across the dashboard. */

export function formatDuration(ms) {
  if (!Number.isFinite(ms) || ms <= 0) return '0s';
  const totalSeconds = Math.round(ms / 1000);
  const minutes = Math.floor(totalSeconds / 60);
  const seconds = totalSeconds % 60;
  if (minutes === 0) return `${seconds}s`;
  if (minutes < 60) return `${minutes}m ${seconds}s`;
  return `${Math.floor(minutes / 60)}h ${minutes % 60}m`;
}

export function formatDateTime(value) {
  if (!value) return '—';
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return '—';
  return date.toLocaleString(undefined, {
    year: 'numeric',
    month: 'short',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
  });
}

export function formatTime(value) {
  if (!value) return '';
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return '';
  return date.toLocaleTimeString(undefined, { hour12: false });
}

export const formatNumber = (value) => new Intl.NumberFormat().format(Number(value) || 0);

/** "https://x.example/a/b?q=1" -> "/a/b?q=1" */
export function pathOf(url) {
  try {
    const parsed = new URL(url);
    return `${parsed.pathname}${parsed.search}` || '/';
  } catch {
    return String(url ?? '');
  }
}

export function truncate(value, maxLength = 60) {
  const text = String(value ?? '');
  return text.length <= maxLength ? text : `${text.slice(0, maxLength - 1)}…`;
}

export const hostOf = (url) => {
  try {
    return new URL(url).host;
  } catch {
    return '';
  }
};
