/**
 * localStorage persistence for scan history.
 *
 * Only scan *results* are stored: target, statistics, findings and endpoints.
 * Nothing that could be a secret is written here - the scanner never collects
 * credentials, and cookie values are redacted server-side before they ever
 * reach a finding.
 */
const HISTORY_KEY = 'vulnscan:history:v1';
const SETTINGS_KEY = 'vulnscan:settings:v1';
const THEME_KEY = 'vulnscan:theme';

/** Keep the browser store small and predictable. */
const LIMITS = {
  scans: 25,
  findings: 300,
  endpoints: 500,
  logEntries: 60,
  evidenceChars: 1500,
};

const readRaw = (key, fallback) => {
  try {
    const raw = window.localStorage.getItem(key);
    return raw ? JSON.parse(raw) : fallback;
  } catch {
    return fallback;
  }
};

const writeRaw = (key, value) => {
  try {
    window.localStorage.setItem(key, JSON.stringify(value));
    return true;
  } catch {
    return false;
  }
};

/** Trim a scan to what the dashboard actually needs to re-render it later. */
export function toStoredScan(scan) {
  return {
    id: scan.id,
    target: scan.target,
    origin: scan.origin,
    status: scan.status,
    startedAt: scan.startedAt,
    completedAt: scan.completedAt || new Date().toISOString(),
    config: scan.config,
    statistics: scan.statistics,
    error: scan.error ?? null,
    findings: (scan.findings || []).slice(0, LIMITS.findings).map((finding) => ({
      ...finding,
      evidence: String(finding.evidence ?? '').slice(0, LIMITS.evidenceChars),
    })),
    endpoints: (scan.endpoints || []).slice(0, LIMITS.endpoints),
    log: (scan.log || []).slice(-LIMITS.logEntries),
    savedAt: new Date().toISOString(),
  };
}

export const loadHistory = () => {
  const history = readRaw(HISTORY_KEY, []);
  return Array.isArray(history) ? history : [];
};

export const loadScan = (id) => loadHistory().find((scan) => scan.id === id) || null;

/**
 * Insert or replace a scan, newest first. If the browser refuses the write
 * (quota), the oldest entries are dropped until it fits.
 * @returns {{history: object[], saved: boolean}}
 */
export function saveScan(scan) {
  const stored = toStoredScan(scan);
  let history = [stored, ...loadHistory().filter((entry) => entry.id !== stored.id)].slice(0, LIMITS.scans);

  while (history.length > 0) {
    if (writeRaw(HISTORY_KEY, history)) return { history, saved: true };
    history = history.slice(0, history.length - 1);
  }
  return { history: loadHistory(), saved: false };
}

export function deleteScan(id) {
  const history = loadHistory().filter((scan) => scan.id !== id);
  writeRaw(HISTORY_KEY, history);
  return history;
}

export function clearHistory() {
  try {
    window.localStorage.removeItem(HISTORY_KEY);
  } catch {
    /* nothing to do - the store is already unavailable */
  }
  return [];
}

/** Update the triage status of one finding inside a stored scan. */
export function updateFindingStatus(scanId, findingId, status) {
  const history = loadHistory().map((scan) => {
    if (scan.id !== scanId) return scan;
    return {
      ...scan,
      findings: scan.findings.map((finding) =>
        finding.id === findingId ? { ...finding, status } : finding,
      ),
    };
  });
  writeRaw(HISTORY_KEY, history);
  return history;
}

/** Approximate size of the stored history, for the history page footer. */
export function historyBytes() {
  try {
    return new Blob([window.localStorage.getItem(HISTORY_KEY) || '']).size;
  } catch {
    return 0;
  }
}

export const loadSettings = (fallback) => ({ ...fallback, ...readRaw(SETTINGS_KEY, {}) });
export const saveSettings = (settings) => writeRaw(SETTINGS_KEY, settings);

export const loadTheme = () => {
  try {
    return window.localStorage.getItem(THEME_KEY) || 'system';
  } catch {
    return 'system';
  }
};

export const saveTheme = (theme) => {
  try {
    if (theme === 'system') window.localStorage.removeItem(THEME_KEY);
    else window.localStorage.setItem(THEME_KEY, theme);
  } catch {
    /* theme preference is best-effort */
  }
};
