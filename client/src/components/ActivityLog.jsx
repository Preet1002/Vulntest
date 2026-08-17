import { useEffect, useRef } from 'react';
import { formatTime } from '../utils/format.js';

const LEVEL_TONE = {
  error: 'text-sev-critical',
  warn: 'text-sev-medium',
  finding: 'text-accent',
  info: 'text-ink-muted',
};

/** Rolling scanner log, newest at the bottom. */
export function ActivityLog({ entries = [], height = 'h-40' }) {
  const scrollRef = useRef(null);
  const pinnedRef = useRef(true);

  // Keep following the tail unless the user has scrolled up to read something.
  useEffect(() => {
    const node = scrollRef.current;
    if (node && pinnedRef.current) node.scrollTop = node.scrollHeight;
  }, [entries.length]);

  const onScroll = () => {
    const node = scrollRef.current;
    if (!node) return;
    pinnedRef.current = node.scrollHeight - node.scrollTop - node.clientHeight < 32;
  };

  if (entries.length === 0) return null;

  return (
    <div className="mt-4 border-t border-line pt-4">
      <p className="mb-2 text-xs font-medium text-ink-muted">Activity</p>
      <div
        ref={scrollRef}
        onScroll={onScroll}
        className={`${height} overflow-y-auto rounded-lg bg-surface-2 p-3`}
        role="log"
        aria-label="Scanner activity"
      >
        <ul className="space-y-1 font-mono text-[11px] leading-relaxed">
          {entries.map((entry, index) => (
            <li key={`${entry.at}-${index}`} className="flex gap-2 break-anywhere">
              <span className="shrink-0 text-ink-muted">{formatTime(entry.at)}</span>
              <span className={LEVEL_TONE[entry.level] || 'text-ink-2'}>{entry.message}</span>
            </li>
          ))}
        </ul>
      </div>
    </div>
  );
}
