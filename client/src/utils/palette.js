/**
 * Chart colours as resolved hex values.
 *
 * Recharts writes colours into SVG attributes, so the charts read from this
 * module (via useTheme) rather than from CSS custom properties. The values are
 * the same tokens defined in index.css - keep the two in step.
 */
export const PALETTES = {
  light: {
    surface: '#fcfcfb',
    grid: '#e1e0d9',
    axis: '#c3c2b7',
    ink: '#0b0b0b',
    ink2: '#52514e',
    muted: '#898781',
    series: '#2a78d6',
    good: '#0ca30c',
    severity: {
      Critical: '#d03b3b',
      High: '#ec835a',
      Medium: '#fab219',
      Low: '#2a78d6',
      Info: '#898781',
    },
    status: {
      '2xx': '#0ca30c',
      '3xx': '#2a78d6',
      '4xx': '#fab219',
      '5xx': '#d03b3b',
      'n/a': '#898781',
    },
  },
  dark: {
    surface: '#1a1a19',
    grid: '#2c2c2a',
    axis: '#383835',
    ink: '#ffffff',
    ink2: '#c3c2b7',
    muted: '#898781',
    series: '#3987e5',
    good: '#0ca30c',
    severity: {
      Critical: '#d03b3b',
      High: '#ec835a',
      Medium: '#fab219',
      Low: '#3987e5',
      Info: '#898781',
    },
    status: {
      '2xx': '#0ca30c',
      '3xx': '#3987e5',
      '4xx': '#fab219',
      '5xx': '#d03b3b',
      'n/a': '#898781',
    },
  },
};

export const paletteFor = (mode) => PALETTES[mode] || PALETTES.light;
