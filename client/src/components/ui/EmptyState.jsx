export function EmptyState({ title, description, action }) {
  return (
    <div className="flex flex-col items-center justify-center gap-2 rounded-lg border border-dashed border-line px-6 py-10 text-center">
      <p className="text-sm font-medium text-ink">{title}</p>
      {description ? <p className="max-w-md text-xs text-ink-muted">{description}</p> : null}
      {action}
    </div>
  );
}
