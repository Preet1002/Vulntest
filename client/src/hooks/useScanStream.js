/**
 * Live scan state.
 *
 * Subscribes to the backend's Server-Sent Events stream and folds each event
 * into a single scan object. If the stream cannot be established (a proxy that
 * buffers, a closed connection), it falls back to polling /status so the
 * dashboard keeps updating either way.
 */
import { useCallback, useEffect, useRef, useState } from 'react';
import { eventStreamUrl, getScan, getScanStatus } from '../services/api.js';

const MAX_LOG_ENTRIES = 200;
const POLL_INTERVAL_MS = 2_500;
const TERMINAL = new Set(['completed', 'stopped', 'failed']);

export const isTerminalStatus = (status) => TERMINAL.has(status);

const appendLog = (log = [], entry) => {
  const next = [...log, entry];
  return next.length > MAX_LOG_ENTRIES ? next.slice(next.length - MAX_LOG_ENTRIES) : next;
};

export function useScanStream(scanId) {
  const [scan, setScan] = useState(null);
  const [connected, setConnected] = useState(false);
  const [streamError, setStreamError] = useState(null);

  const sourceRef = useRef(null);
  const pollRef = useRef(null);

  const stopPolling = useCallback(() => {
    if (pollRef.current) {
      clearInterval(pollRef.current);
      pollRef.current = null;
    }
  }, []);

  /** Used when the live stream is unavailable. */
  const startPolling = useCallback(
    (id) => {
      if (pollRef.current) return;
      pollRef.current = setInterval(async () => {
        try {
          const status = await getScanStatus(id);
          setScan((previous) => ({ ...(previous || { id }), ...status, log: status.log || previous?.log || [] }));
          if (status.finished) {
            const full = await getScan(id);
            setScan(full.scan);
            stopPolling();
          }
        } catch (error) {
          setStreamError(error.message);
          stopPolling();
        }
      }, POLL_INTERVAL_MS);
    },
    [stopPolling],
  );

  useEffect(() => {
    if (!scanId) {
      setScan(null);
      setConnected(false);
      setStreamError(null);
      return undefined;
    }

    let cancelled = false;
    setStreamError(null);

    const source = new EventSource(eventStreamUrl(scanId));
    sourceRef.current = source;

    const on = (type, handler) =>
      source.addEventListener(type, (event) => {
        if (cancelled) return;
        try {
          handler(JSON.parse(event.data));
        } catch {
          /* ignore malformed frames rather than tearing down the stream */
        }
      });

    source.onopen = () => {
      if (cancelled) return;
      setConnected(true);
      setStreamError(null);
      stopPolling();
    };

    on('snapshot', (event) => setScan(event.scan));

    on('status', (event) =>
      setScan((previous) => (previous ? { ...previous, status: event.status, phase: event.phase } : previous)),
    );

    on('progress', (event) =>
      setScan((previous) =>
        previous
          ? {
              ...previous,
              progress: event.progress,
              currentUrl: event.currentUrl,
              statistics: event.statistics || previous.statistics,
              phase: event.phase ?? previous.phase,
              status: event.status ?? previous.status,
            }
          : previous,
      ),
    );

    on('endpoint', (event) =>
      setScan((previous) => {
        if (!previous) return previous;
        const endpoints = previous.endpoints || [];
        const exists = endpoints.some((endpoint) => endpoint.id === event.endpoint.id);
        const next = exists
          ? endpoints.map((endpoint) => (endpoint.id === event.endpoint.id ? event.endpoint : endpoint))
          : [...endpoints, event.endpoint];
        return { ...previous, endpoints: next };
      }),
    );

    on('finding', (event) =>
      setScan((previous) => {
        if (!previous) return previous;
        if ((previous.findings || []).some((finding) => finding.id === event.finding.id)) return previous;
        return { ...previous, findings: [...(previous.findings || []), event.finding] };
      }),
    );

    on('log', (event) =>
      setScan((previous) =>
        previous
          ? { ...previous, log: appendLog(previous.log, { at: event.at, level: event.level, message: event.message }) }
          : previous,
      ),
    );

    on('done', (event) => {
      setScan((previous) =>
        previous
          ? {
              ...previous,
              status: event.status,
              statistics: event.statistics || previous.statistics,
              progress: event.progress ?? previous.progress,
              completedAt: event.completedAt || new Date().toISOString(),
              error: event.error ?? previous.error,
              currentUrl: null,
            }
          : previous,
      );
      source.close();
      setConnected(false);
    });

    source.onerror = () => {
      if (cancelled) return;
      setConnected(false);
      // readyState CLOSED means the browser gave up; fall back to polling.
      if (source.readyState === EventSource.CLOSED) {
        setStreamError('Live updates unavailable - falling back to polling.');
        startPolling(scanId);
      }
    };

    return () => {
      cancelled = true;
      source.close();
      sourceRef.current = null;
      stopPolling();
    };
  }, [scanId, startPolling, stopPolling]);

  /** Replace local state with the authoritative record (used after a stop). */
  const refresh = useCallback(async () => {
    if (!scanId) return;
    try {
      const { scan: full } = await getScan(scanId);
      setScan(full);
    } catch (error) {
      setStreamError(error.message);
    }
  }, [scanId]);

  return {
    scan,
    connected,
    streamError,
    refresh,
    finished: scan ? isTerminalStatus(scan.status) : false,
  };
}
