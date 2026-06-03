'use client';

import { useState, Suspense } from 'react';
import {
  PieChart, Pie, Cell, BarChart, Bar, LineChart, Line,
  XAxis, YAxis, Tooltip, ResponsiveContainer, CartesianGrid,
} from 'recharts';
import { ScansProvider, useScans } from '@/components/ScansProvider';
import { Pagination, paginate } from '@/components/Pagination';
import { useFilter, StatCard, useRechartsTheme, cls } from '@agnistack/omniflow-ui';
import { SeverityBadge } from '@/components/SeverityBadge';

const SEVERITY_COLORS: Record<string, string> = {
  CRITICAL: '#991b1b',
  HIGH:     '#dc2626',
  MEDIUM:   '#ea580c',
  LOW:      '#ca8a04',
  UNKNOWN:  '#475569',
};

function fmtTime(iso: string) {
  return new Date(iso).toLocaleString('en-US', { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
}

function Overview() {
  const { scans, isLoading } = useScans();
  const [scansPage, setScansPage] = useState(0);
  const { tooltipStyle, gridStroke, axisTick, pieLabelStroke } = useRechartsTheme();

  if (isLoading) return <p className="text-gray-500 dark:text-slate-500 text-sm">Loading scan history...</p>;

  if (!scans.length) return (
    <div className="text-center py-20">
      <p className="text-gray-500 dark:text-slate-400 mb-2">No scans found.</p>
      <p className="text-gray-400 dark:text-slate-600 text-sm">
        Run a Trivy scan and POST the JSON report to{' '}
        <code className="text-gray-500 dark:text-slate-500">/api/v1/ingest/trivy-scan-report</code>.
      </p>
    </div>
  );

  // Aggregate across all scans
  const totalVulns    = scans.reduce((s, sc) => s + (sc.fields?.totalVulns ?? 0), 0);
  const totalCritical = scans.reduce((s, sc) => s + (sc.fields?.severityCounts?.CRITICAL ?? 0), 0);
  const totalHigh     = scans.reduce((s, sc) => s + (sc.fields?.severityCounts?.HIGH ?? 0), 0);
  const totalMedium   = scans.reduce((s, sc) => s + (sc.fields?.severityCounts?.MEDIUM ?? 0), 0);
  const totalLow      = scans.reduce((s, sc) => s + (sc.fields?.severityCounts?.LOW ?? 0), 0);
  const totalFixable  = scans.reduce((s, sc) => s + (sc.fields?.fixableCount ?? 0), 0);
  const totalPkgs     = scans.reduce((s, sc) => s + (sc.fields?.packageCount ?? 0), 0);

  // Severity distribution pie
  const severityPie = [
    { name: 'Critical', value: totalCritical, color: SEVERITY_COLORS.CRITICAL },
    { name: 'High',     value: totalHigh,     color: SEVERITY_COLORS.HIGH },
    { name: 'Medium',   value: totalMedium,   color: SEVERITY_COLORS.MEDIUM },
    { name: 'Low',      value: totalLow,      color: SEVERITY_COLORS.LOW },
  ].filter(d => d.value > 0);

  // Vulnerabilities over time (reversed for chronological order)
  const trendData = [...scans].reverse().map(sc => ({
    t:        fmtTime(sc.timestamp),
    critical: sc.fields?.severityCounts?.CRITICAL ?? 0,
    high:     sc.fields?.severityCounts?.HIGH ?? 0,
    medium:   sc.fields?.severityCounts?.MEDIUM ?? 0,
    low:      sc.fields?.severityCounts?.LOW ?? 0,
    total:    sc.fields?.totalVulns ?? 0,
  }));

  // Top 10 vulnerable packages across all scans
  const pkgVulnCounts: Record<string, number> = {};
  scans.forEach(sc => {
    (sc.fields?.vulnerabilities ?? []).forEach(v => {
      pkgVulnCounts[v.pkgName] = (pkgVulnCounts[v.pkgName] ?? 0) + 1;
    });
  });
  const topPkgs = Object.entries(pkgVulnCounts)
    .map(([name, count]) => ({ name, count }))
    .sort((a, b) => b.count - a.count)
    .slice(0, 10);

  const cardCls    = cls.card + ' p-4';
  const headingCls = cls.heading + ' mb-3';

  return (
    <div className="max-w-6xl space-y-6">

      {/* KPIs */}
      <div className="grid grid-cols-2 md:grid-cols-6 gap-3">
        <StatCard label="Total Vulns" value={totalVulns} />
        <StatCard label="Critical" value={totalCritical}
          tone={totalCritical > 0 ? 'danger' : 'success'} />
        <StatCard label="High" value={totalHigh}
          tone={totalHigh > 0 ? 'danger' : 'success'} />
        <StatCard label="Medium" value={totalMedium}
          tone={totalMedium > 0 ? 'warn' : 'success'} />
        <StatCard label="Low" value={totalLow} />
        <StatCard label="Fixable" value={totalFixable}
          sub={`of ${totalVulns}`}
          tone={totalFixable > 0 ? 'success' : 'neutral'} />
      </div>

      {/* Charts row */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <div className={cardCls}>
          <p className={headingCls}>Severity Distribution</p>
          {severityPie.length === 0 ? (
            <p className="text-green-600 dark:text-green-400 text-sm py-8 text-center">No vulnerabilities found.</p>
          ) : (
            <ResponsiveContainer width="100%" height={220}>
              <PieChart>
                <Pie data={severityPie} dataKey="value" nameKey="name" cx="50%" cy="50%" outerRadius={80}
                  label={d => `${d.name} (${d.value})`} labelLine={{ stroke: pieLabelStroke }}>
                  {severityPie.map((e, i) => <Cell key={i} fill={e.color} />)}
                </Pie>
                <Tooltip contentStyle={tooltipStyle} />
              </PieChart>
            </ResponsiveContainer>
          )}
        </div>

        <div className={cardCls}>
          <p className={headingCls}>Top 10 Vulnerable Packages</p>
          {topPkgs.length === 0 ? (
            <p className="text-gray-400 dark:text-slate-600 text-sm py-8 text-center">No vulnerability data.</p>
          ) : (
            <ResponsiveContainer width="100%" height={220}>
              <BarChart data={topPkgs} layout="vertical">
                <CartesianGrid strokeDasharray="3 3" stroke={gridStroke} />
                <XAxis type="number" tick={axisTick} />
                <YAxis type="category" dataKey="name" tick={{ ...axisTick, fontSize: 10 }} width={130} />
                <Tooltip contentStyle={tooltipStyle} />
                <Bar dataKey="count" name="Vulnerabilities" fill="#dc2626" />
              </BarChart>
            </ResponsiveContainer>
          )}
        </div>
      </div>

      {/* Trend */}
      <div className={cardCls}>
        <p className={headingCls}>Vulnerabilities Over Time</p>
        <ResponsiveContainer width="100%" height={200}>
          <LineChart data={trendData}>
            <CartesianGrid strokeDasharray="3 3" stroke={gridStroke} />
            <XAxis dataKey="t" tick={false} />
            <YAxis tick={axisTick} />
            <Tooltip contentStyle={tooltipStyle} />
            <Line type="monotone" dataKey="critical" stroke={SEVERITY_COLORS.CRITICAL} strokeWidth={2} dot={false} name="Critical" />
            <Line type="monotone" dataKey="high"     stroke={SEVERITY_COLORS.HIGH}     strokeWidth={2} dot={false} name="High" />
            <Line type="monotone" dataKey="medium"   stroke={SEVERITY_COLORS.MEDIUM}   strokeWidth={2} dot={false} name="Medium" />
            <Line type="monotone" dataKey="low"      stroke={SEVERITY_COLORS.LOW}      strokeWidth={1} dot={false} name="Low" />
          </LineChart>
        </ResponsiveContainer>
      </div>

      {/* Recent scans table */}
      {(() => {
        const { paged, total: sTotal, totalPages } = paginate(scans, scansPage);
        return (
          <div className={cardCls}>
            <p className={headingCls}>Recent Scans ({scans.length})</p>
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className={cls.table.header}>
                    <th className="text-left py-2 px-2">Artifact</th>
                    <th className="text-left py-2 px-2">Type</th>
                    <th className="text-left py-2 px-2">OS</th>
                    <th className="text-right py-2 px-2">Total</th>
                    <th className="text-right py-2 px-2">Critical</th>
                    <th className="text-right py-2 px-2">High</th>
                    <th className="text-right py-2 px-2">Medium</th>
                    <th className="text-right py-2 px-2">Low</th>
                    <th className="text-left py-2 px-2">Time</th>
                  </tr>
                </thead>
                <tbody>
                  {paged.map(sc => (
                    <tr key={sc.id} className={cls.table.row}>
                      <td className="py-2 px-2 text-gray-700 dark:text-slate-300 font-mono text-xs max-w-[200px] truncate" title={sc.fields?.artifactName}>
                        {sc.fields?.artifactName ?? '--'}
                      </td>
                      <td className="py-2 px-2 text-xs text-gray-500 dark:text-slate-400">
                        {sc.fields?.artifactType?.replace('_', ' ') ?? '--'}
                      </td>
                      <td className="py-2 px-2 text-xs text-gray-500 dark:text-slate-400">
                        {sc.fields?.osFamily ? `${sc.fields.osFamily} ${sc.fields.osName}` : '--'}
                      </td>
                      <td className="py-2 px-2 text-right font-semibold">{sc.fields?.totalVulns ?? 0}</td>
                      <td className="py-2 px-2 text-right">
                        <span className={sc.fields?.severityCounts?.CRITICAL ? 'text-red-700 dark:text-red-400 font-semibold' : 'text-gray-300 dark:text-slate-600'}>
                          {sc.fields?.severityCounts?.CRITICAL ?? 0}
                        </span>
                      </td>
                      <td className="py-2 px-2 text-right">
                        <span className={sc.fields?.severityCounts?.HIGH ? 'text-red-600 dark:text-red-400' : 'text-gray-300 dark:text-slate-600'}>
                          {sc.fields?.severityCounts?.HIGH ?? 0}
                        </span>
                      </td>
                      <td className="py-2 px-2 text-right">
                        <span className={sc.fields?.severityCounts?.MEDIUM ? 'text-orange-600 dark:text-orange-400' : 'text-gray-300 dark:text-slate-600'}>
                          {sc.fields?.severityCounts?.MEDIUM ?? 0}
                        </span>
                      </td>
                      <td className="py-2 px-2 text-right">
                        <span className={sc.fields?.severityCounts?.LOW ? 'text-yellow-600 dark:text-yellow-400' : 'text-gray-300 dark:text-slate-600'}>
                          {sc.fields?.severityCounts?.LOW ?? 0}
                        </span>
                      </td>
                      <td className="py-2 px-2 text-gray-400 dark:text-slate-500 text-xs">{fmtTime(sc.timestamp)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <Pagination page={scansPage} totalPages={totalPages} total={sTotal} onPageChange={setScansPage} />
          </div>
        );
      })()}
    </div>
  );
}

function OverviewContent() {
  const { filter: f } = useFilter();
  return (
    <ScansProvider filter={{
      projectName: f.projectName || undefined,
      status:      f.status      || undefined,
      limit:       Number(f.limit) || 50,
    }}>
      <Overview />
    </ScansProvider>
  );
}

export default function OverviewPage() {
  return <Suspense fallback={<p className="text-gray-500 text-sm p-4">Loading...</p>}><OverviewContent /></Suspense>;
}