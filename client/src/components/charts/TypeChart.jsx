import {
  Bar,
  BarChart,
  CartesianGrid,
  LabelList,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts';
import { ChartCard, ChartTooltip } from './ChartCard.jsx';
import { usePalette } from '../../hooks/useTheme.jsx';
import { countByType } from '../../utils/severity.js';
import { truncate } from '../../utils/format.js';

const MAX_BARS = 8;

/**
 * Findings by vulnerability type - one series, so every bar takes the same
 * colour. Bar length already encodes the count; hue would add nothing.
 */
export function TypeChart({ findings = [] }) {
  const palette = usePalette();
  const all = countByType(findings);

  // Past eight categories the tail folds into "Other" rather than growing the chart.
  const head = all.slice(0, MAX_BARS);
  const tail = all.slice(MAX_BARS);
  const data = [
    ...head.map((entry) => ({ name: entry.type, count: entry.count })),
    ...(tail.length
      ? [{ name: `Other (${tail.length} types)`, count: tail.reduce((sum, entry) => sum + entry.count, 0) }]
      : []),
  ];
  const rows = data.map((entry) => ({ label: entry.name, value: entry.count }));

  return (
    <ChartCard
      title="Vulnerabilities by type"
      subtitle={all.length > MAX_BARS ? `Top ${MAX_BARS} of ${all.length} types` : 'All reported types'}
      rows={rows}
      valueLabel="Findings"
      empty={{ title: 'No findings yet', description: 'Detected issue types are grouped here.' }}
    >
      <ResponsiveContainer width="100%" height={Math.max(160, data.length * 34 + 24)}>
        <BarChart data={data} layout="vertical" margin={{ top: 4, right: 28, bottom: 4, left: 4 }} barCategoryGap="30%">
          <CartesianGrid horizontal={false} stroke={palette.grid} />
          <XAxis type="number" hide allowDecimals={false} />
          <YAxis
            type="category"
            dataKey="name"
            width={168}
            tickLine={false}
            axisLine={{ stroke: palette.axis }}
            tick={{ fill: palette.muted, fontSize: 12 }}
            tickFormatter={(value) => truncate(value, 24)}
          />
          <Tooltip cursor={{ fill: palette.grid, fillOpacity: 0.35 }} content={<ChartTooltip suffix="findings" />} />
          <Bar dataKey="count" fill={palette.series} barSize={14} radius={[0, 4, 4, 0]} isAnimationActive={false}>
            <LabelList
              dataKey="count"
              position="right"
              offset={8}
              style={{ fill: palette.ink2, fontSize: 12 }}
            />
          </Bar>
        </BarChart>
      </ResponsiveContainer>
    </ChartCard>
  );
}
