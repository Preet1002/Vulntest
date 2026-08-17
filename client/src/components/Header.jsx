import { NavLink } from 'react-router-dom';
import { useTheme } from '../hooks/useTheme.jsx';

const NAV = [
  { to: '/', label: 'Dashboard', end: true },
  { to: '/history', label: 'Scan history' },
  { to: '/about', label: 'Safe use' },
];

const THEMES = [
  { value: 'light', label: 'Light' },
  { value: 'dark', label: 'Dark' },
  { value: 'system', label: 'Auto' },
];

export function Header() {
  const { theme, setTheme } = useTheme();

  return (
    <header className="border-b border-line bg-surface-1">
      <div className="mx-auto flex max-w-[1400px] flex-wrap items-center justify-between gap-4 px-6 py-4">
        <div className="flex items-center gap-3">
          <span aria-hidden="true" className="grid h-9 w-9 place-items-center rounded-lg bg-accent/10 text-accent">
            <svg viewBox="0 0 24 24" className="h-5 w-5" fill="none" stroke="currentColor" strokeWidth="1.8">
              <path d="M12 3 5 6v5.5c0 4.2 2.9 8.1 7 9.5 4.1-1.4 7-5.3 7-9.5V6l-7-3Z" strokeLinejoin="round" />
              <path d="m9.5 12 1.8 1.8L15 10" strokeLinecap="round" strokeLinejoin="round" />
            </svg>
          </span>
          <div>
            <h1 className="text-base font-semibold leading-tight tracking-tight text-ink">
              Web Vulnerability Scanner
            </h1>
            <p className="text-xs text-ink-muted">Authorized Security Testing</p>
          </div>
        </div>

        <div className="flex flex-wrap items-center gap-4">
          <nav aria-label="Primary">
            <ul className="flex items-center gap-1">
              {NAV.map((item) => (
                <li key={item.to}>
                  <NavLink
                    to={item.to}
                    end={item.end}
                    className={({ isActive }) =>
                      `rounded-lg px-3 py-1.5 text-sm transition-colors ${
                        isActive ? 'bg-surface-2 text-ink' : 'text-ink-2 hover:bg-surface-2'
                      }`
                    }
                  >
                    {item.label}
                  </NavLink>
                </li>
              ))}
            </ul>
          </nav>

          <div className="flex rounded-lg border border-line p-0.5" role="group" aria-label="Colour theme">
            {THEMES.map((option) => (
              <button
                key={option.value}
                type="button"
                onClick={() => setTheme(option.value)}
                aria-pressed={theme === option.value}
                className={`rounded-md px-2 py-1 text-xs transition-colors ${
                  theme === option.value ? 'bg-surface-2 text-ink' : 'text-ink-muted hover:text-ink-2'
                }`}
              >
                {option.label}
              </button>
            ))}
          </div>
        </div>
      </div>
    </header>
  );
}
