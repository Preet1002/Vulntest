import { createContext, useCallback, useContext, useEffect, useMemo, useState } from 'react';
import { loadTheme, saveTheme } from '../utils/storage.js';
import { paletteFor } from '../utils/palette.js';

const ThemeContext = createContext(null);

const systemPrefersDark = () =>
  typeof window !== 'undefined' && window.matchMedia?.('(prefers-color-scheme: dark)').matches;

/**
 * Theme state for the whole app. `theme` is the user's choice
 * (system | light | dark); `mode` is what is actually rendered.
 */
export function ThemeProvider({ children }) {
  const [theme, setThemeState] = useState(() => loadTheme());
  const [systemDark, setSystemDark] = useState(() => systemPrefersDark());

  useEffect(() => {
    const query = window.matchMedia('(prefers-color-scheme: dark)');
    const listener = (event) => setSystemDark(event.matches);
    query.addEventListener('change', listener);
    return () => query.removeEventListener('change', listener);
  }, []);

  const mode = theme === 'system' ? (systemDark ? 'dark' : 'light') : theme;

  useEffect(() => {
    const root = document.documentElement;
    if (theme === 'system') root.removeAttribute('data-theme');
    else root.setAttribute('data-theme', theme);
  }, [theme]);

  const setTheme = useCallback((next) => {
    setThemeState(next);
    saveTheme(next);
  }, []);

  const value = useMemo(
    () => ({ theme, mode, setTheme, palette: paletteFor(mode) }),
    [theme, mode, setTheme],
  );

  return <ThemeContext.Provider value={value}>{children}</ThemeContext.Provider>;
}

export function useTheme() {
  const context = useContext(ThemeContext);
  if (!context) throw new Error('useTheme must be used inside a ThemeProvider.');
  return context;
}

/** Convenience for chart components. */
export const usePalette = () => useTheme().palette;
