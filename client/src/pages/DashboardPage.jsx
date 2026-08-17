import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { Link } from 'react-router-dom';
import { ScanLauncher } from '../components/ScanLauncher.jsx';
import { ConfigDialog } from '../components/ConfigDialog.jsx';
import { ProgressPanel } from '../components/ProgressPanel.jsx';
import { ScanResults } from '../components/ScanResults.jsx';
import { Card } from '../components/ui/Card.jsx';
import { EmptyState } from '../components/ui/EmptyState.jsx';
import { useScanStream } from '../hooks/useScanStream.js';
import { useScanHistory } from '../hooks/useScanHistory.js';
import { getScanConfig, startScan, stopScan } from '../services/api.js';
import { loadSettings, saveSettings, updateFindingStatus } from '../utils/storage.js';

const ACTIVE_SCAN_KEY = 'vulnscan:activeScanId';

const FALLBACK_CONFIG = {
  maxPages: 100,
  maxDepth: 3,
  concurrency: 2,
  requestTimeoutMs: 10_000,
  delayMs: 250,
  maxRequests: 1_500,
  maxScanDurationMs: 600_000,
  respectRobots: true,
  allowSubdomains: false,
  testForms: true,
  testPostForms: false,
  checks: { xss: true, sqli: true, pathTraversal: true, passive: true },
};

const FALLBACK_LIMITS = {
  maxPages: 250,
  maxDepth: 6,
  concurrency: 4,
  requestTimeoutMs: 30_000,
  delayMs: 5_000,
  maxRequests: 4_000,
  maxScanDurationMs: 1_200_000,
};

export function DashboardPage() {
  const [target, setTarget] = useState('');
  const [authorized, setAuthorized] = useState(false);
  const [config, setConfig] = useState(() => loadSettings(FALLBACK_CONFIG));
  const [limits, setLimits] = useState(FALLBACK_LIMITS);
  const [privateTargetsAllowed, setPrivateTargetsAllowed] = useState(false);
  const [dialogOpen, setDialogOpen] = useState(false);
  const [starting, setStarting] = useState(false);
  const [error, setError] = useState(null);
  const [statusOverrides, setStatusOverrides] = useState({});

  const [activeScanId, setActiveScanId] = useState(() => {
    try {
      return window.localStorage.getItem(ACTIVE_SCAN_KEY) || null;
    } catch {
      return null;
    }
  });

  const { scan, connected, streamError, finished, refresh } = useScanStream(activeScanId);
  const { save, quotaWarning } = useScanHistory();
  const savedRef = useRef(new Set());

  // Publish the server's real limits so the config dialog cannot offer more.
  useEffect(() => {
    let cancelled = false;
    getScanConfig()
      .then(({ limits: serverLimits, allowPrivateTargets }) => {
        if (cancelled) return;
        if (serverLimits) setLimits(serverLimits);
        setPrivateTargetsAllowed(Boolean(allowPrivateTargets));
      })
      .catch(() => {
        /* keep the fallbacks - the launcher will surface any real API problem */
      });
    return () => {
      cancelled = true;
    };
  }, []);

  // Remember the running scan so a page reload re-attaches to its stream.
  useEffect(() => {
    try {
      if (activeScanId) window.localStorage.setItem(ACTIVE_SCAN_KEY, activeScanId);
      else window.localStorage.removeItem(ACTIVE_SCAN_KEY);
    } catch {
      /* non-fatal */
    }
  }, [activeScanId]);

  const findingsWithStatus = useMemo(() => {
    if (!scan?.findings) return [];
    return scan.findings.map((finding) =>
      statusOverrides[finding.id] ? { ...finding, status: statusOverrides[finding.id] } : finding,
    );
  }, [scan?.findings, statusOverrides]);

  // Persist the completed scan to localStorage exactly once.
  useEffect(() => {
    if (!scan || !finished || savedRef.current.has(scan.id)) return;
    savedRef.current.add(scan.id);
    save({ ...scan, findings: findingsWithStatus });
    try {
      window.localStorage.removeItem(ACTIVE_SCAN_KEY);
    } catch {
      /* non-fatal */
    }
  }, [scan, finished, findingsWithStatus, save]);

  const onStart = useCallback(async () => {
    setStarting(true);
    setError(null);
    setStatusOverrides({});
    try {
      const { scan: created } = await startScan({ target: target.trim(), config, authorized });
      savedRef.current.delete(created.id);
      setActiveScanId(created.id);
    } catch (requestError) {
      setError(requestError.message);
    } finally {
      setStarting(false);
    }
  }, [target, config, authorized]);

  const onStop = useCallback(async () => {
    if (!activeScanId) return;
    setStarting(true);
    try {
      await stopScan(activeScanId);
      await refresh();
    } catch (requestError) {
      setError(requestError.message);
    } finally {
      setStarting(false);
    }
  }, [activeScanId, refresh]);

  const onSaveConfig = (next) => {
    setConfig(next);
    saveSettings(next);
    setDialogOpen(false);
  };

  const onFindingStatusChange = (findingId, status) => {
    setStatusOverrides((previous) => ({ ...previous, [findingId]: status }));
    // A finished scan is already in localStorage, so triage has to be written
    // through - the save-once effect will not run again for it.
    if (finished && scan?.id) updateFindingStatus(scan.id, findingId, status);
  };

  const running = Boolean(scan) && !finished;

  return (
    <div className="space-y-4">
      <ScanLauncher
        target={target}
        onTargetChange={setTarget}
        authorized={authorized}
        onAuthorizedChange={setAuthorized}
        onStart={onStart}
        onStop={onStop}
        onOpenConfig={() => setDialogOpen(true)}
        running={running}
        busy={starting}
        error={error}
        config={config}
      />

      {privateTargetsAllowed ? (
        <Card className="border-sev-medium/40">
          <p className="text-xs text-ink-2">
            <span className="font-medium text-ink">Private targets are enabled on this backend.</span>{' '}
            ALLOW_PRIVATE_TARGETS is set, so localhost and private network addresses can be scanned. That is useful
            for testing your own app in development, and unsafe anywhere someone else can reach this API - the
            backend can then be used to reach internal hosts. Unset it before deploying.
          </p>
        </Card>
      ) : null}

      {quotaWarning ? (
        <Card className="border-sev-medium/40">
          <p className="text-xs text-ink-2">
            This scan could not be saved to localStorage - the browser store is full. Delete older scans from{' '}
            <Link to="/history" className="text-accent underline underline-offset-2">
              scan history
            </Link>{' '}
            to make room.
          </p>
        </Card>
      ) : null}

      {scan ? (
        <>
          <ProgressPanel scan={scan} connected={connected} streamError={streamError} />
          <ScanResults
            scan={{ ...scan, findings: findingsWithStatus }}
            onFindingStatusChange={onFindingStatusChange}
          />
        </>
      ) : (
        <Card>
          <EmptyState
            title="No scan running"
            description="Enter a URL you are authorized to test and start a scan. The crawler maps the site, then safe checks run against the parameters it found - reflection analysis for XSS, read-only comparisons for SQL injection and path traversal, plus passive header and cookie checks."
            action={
              <Link to="/history" className="mt-2 text-xs text-accent underline underline-offset-2">
                Open a previous scan
              </Link>
            }
          />
        </Card>
      )}

      <ConfigDialog
        open={dialogOpen}
        config={config}
        limits={limits}
        onSave={onSaveConfig}
        onClose={() => setDialogOpen(false)}
      />
    </div>
  );
}
