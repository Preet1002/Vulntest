const VARIANTS = {
  primary: 'bg-accent text-white hover:opacity-90 disabled:opacity-40',
  danger: 'bg-sev-critical text-white hover:opacity-90 disabled:opacity-40',
  outline: 'border border-line bg-surface-1 text-ink hover:bg-surface-2 disabled:opacity-40',
  ghost: 'text-ink-2 hover:bg-surface-2 disabled:opacity-40',
};

const SIZES = {
  sm: 'px-2.5 py-1.5 text-xs',
  md: 'px-3.5 py-2 text-sm',
};

export function Button({
  variant = 'primary',
  size = 'md',
  className = '',
  type = 'button',
  children,
  ...props
}) {
  return (
    <button
      type={type}
      className={`inline-flex items-center justify-center gap-1.5 rounded-lg font-medium transition-colors disabled:cursor-not-allowed ${VARIANTS[variant]} ${SIZES[size]} ${className}`}
      {...props}
    >
      {children}
    </button>
  );
}
