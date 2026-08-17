import {
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  LabelList,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts';
import { ChartCard, ChartTooltip } from './ChartCard.jsx';
import { usePalette } from '../../hooks/useTheme.jsx';
import { SEVERITY_ORDER, countBySeverity } from '../../utils/severity.js';

/**
 * Findings by severity.
 *
 * Horizontal bars keep the severity names on the axis, so the status colours
 * reinforce an identity the reader already has in text.
 */
export function SeverityChart({ findings = [] }) {
  const palette = usePalette();
  const counts = countBySeverity(findings);
  const data = SEVERITY_ORDER.map((severity) => ({ name: severity, count: counts[severity] }));
  const rows = data.map((entry) => ({ label: entry.name, value: entry.count }));

  return (
    <ChartCard
      title="Vulnerabilities by severity"
      subtitle="Counts for the current scan"
      rows={rows}
      valueLabel="Findings"
      empty={{ title: 'No findings yet', description: 'Severity counts appear as the scan reports findings.' }}
    >
      <ResponsiveContainer width="100%" height={200}>
        <BarChart data={data} layout="vertical" margin={{ top: 4, right: 28, bottom: 4, left: 4 }} barCategoryGap="30%">
          <CartesianGrid horizontal={false} stroke={palette.grid} />
          <XAxis type="number" hide allowDecimals={false} />
          <YAxis
            type="category"
            dataKey="name"
            width={64}
            tickLine={false}
            axisLine={{ stroke: palette.axis }}
            tick={{ fill: palette.muted, fontSize: 12 }}
          />
          <Tooltip cursor={{ fill: palette.grid, fillOpacity: 0.35 }} content={<ChartTooltip suffix="findings" />} />
          <Bar dataKey="count" barSize={14} radius={[0, 4, 4, 0]} isAnimationActive={false}>
            {data.map((entry) => (
              <Cell key={entry.name} fill={palette.severity[entry.name]} />
            ))}
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
