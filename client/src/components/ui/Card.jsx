/** Card frame used by every panel on the dashboard. */
export function Card({ children, className = '', padded = true }) {
  return (
    <section
      className={`rounded-xl border border-line bg-surface-1 ${padded ? 'p-5' : ''} ${className}`}
    >
      {children}
    </section>
  );
}

export function CardHeader({ title, subtitle, actions, id }) {
  return (
    <header className="mb-4 flex flex-wrap items-start justify-between gap-3">
      <div>
        <h2 id={id} className="text-sm font-semibold tracking-tight text-ink">
          {title}
        </h2>
        {subtitle ? <p className="mt-0.5 text-xs text-ink-muted">{subtitle}</p> : null}
      </div>
      {actions ? <div className="flex items-center gap-2">{actions}</div> : null}
    </header>
  );
}
