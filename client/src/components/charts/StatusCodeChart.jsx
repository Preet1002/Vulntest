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
import { countByStatusClass } from '../../utils/severity.js';

/**
 * Endpoints by HTTP status class. Success/client-error/server-error is a real
 * status meaning, so the status palette applies - and each bar is named on the
 * axis, so the colour never carries the distinction alone.
 */
export function StatusCodeChart({ endpoints = [] }) {
  const palette = usePalette();
  const data = countByStatusClass(endpoints).map((entry) => ({
    name: entry.label,
    key: entry.key,
    count: entry.count,
  }));
  const rows = data.map((entry) => ({ label: entry.name, value: entry.count }));

  return (
    <ChartCard
      title="Endpoint status codes"
      subtitle="Responses seen while crawling"
      rows={rows}
      valueLabel="Endpoints"
      empty={{ title: 'No endpoints yet', description: 'Status codes appear as the crawler visits pages.' }}
    >
      <ResponsiveContainer width="100%" height={Math.max(160, data.length * 34 + 24)}>
        <BarChart data={data} layout="vertical" margin={{ top: 4, right: 28, bottom: 4, left: 4 }} barCategoryGap="30%">
          <CartesianGrid horizontal={false} stroke={palette.grid} />
          <XAxis type="number" hide allowDecimals={false} />
          <YAxis
            type="category"
            dataKey="name"
            width={120}
            tickLine={false}
            axisLine={{ stroke: palette.axis }}
            tick={{ fill: palette.muted, fontSize: 12 }}
          />
          <Tooltip cursor={{ fill: palette.grid, fillOpacity: 0.35 }} content={<ChartTooltip suffix="endpoints" />} />
          <Bar dataKey="count" barSize={14} radius={[0, 4, 4, 0]} isAnimationActive={false}>
            {data.map((entry) => (
              <Cell key={entry.key} fill={palette.status[entry.key]} />
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
