'use client';

import { useState, useMemo, Suspense } from 'react';
import { ScansProvider, useScans } from '@/components/ScansProvider';
import { Pagination, paginate } from '@/components/Pagination';
import { useFilter, StatCard, cls } from '@agnistack/omniflow-ui';
import type { Package } from '@/lib/api';

function fmtTime(iso: string) {
  return new Date(iso).toLocaleString('en-US', { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
}

const SEVERITY_MINI_COLORS: Record<string, string> = {
  CRITICAL: '#991b1b',
  HIGH:     '#dc2626',
  MEDIUM:   '#ea580c',
  LOW:      '#ca8a04',
};

function Packages() {
  const { scans, isLoading } = useScans();
  const [scanIdx, setScanIdx] = useState(0);
  const [pkgPage, setPkgPage] = useState(0);
  const [search, setSearch] = useState('');

  if (isLoading) return <p className="text-gray-500 dark:text-slate-500 text-sm">Loading...</p>;
  if (!scans.length) return <p className="text-gray-500 dark:text-slate-500 text-sm">No scans ingested yet.</p>;

  const scan = scans[scanIdx];
  const pkgs = scan?.fields?.packages ?? [];
  const vulns = scan?.fields?.vulnerabilities ?? [];

  // Compute vulnerability counts per package
  const pkgVulnMap = useMemo(() => {
    const map: Record<string, { CRITICAL: number; HIGH: number; MEDIUM: number; LOW: number; UNKNOWN: number; total: number }> = {};
    vulns.forEach(v => {
      if (!map[v.pkgName]) map[v.pkgName] = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, UNKNOWN: 0, total: 0 };
      const sev = v.severity.toUpperCase() as keyof typeof map[string];
      if (sev in map[v.pkgName]) map[v.pkgName][sev]++;
      map[v.pkgName].total++;
    });
    return map;
  }, [vulns]);

  const totalPkgs    = pkgs.length;
  const vulnerablePkgs = Object.keys(pkgVulnMap).length;
  const osPkgs       = pkgs.filter(p => p.class === 'os-pkgs').length;
  const langPkgs     = pkgs.filter(p => p.class === 'lang-pkgs').length;

  // Filtered packages
  const filtered = useMemo(() => {
    if (!search.trim()) return pkgs;
    const q = search.toLowerCase();
    return pkgs.filter(p =>
      p.name.toLowerCase().includes(q) ||
      p.type.toLowerCase().includes(q) ||
      p.version.toLowerCase().includes(q)
    );
  }, [pkgs, search]);

  const cardCls    = cls.card + ' p-4';
  const headingCls = cls.heading + ' mb-3';

  return (
    <div className="max-w-6xl space-y-6">
      {/* Scan selector */}
      <div className="flex items-center gap-3 flex-wrap">
        <label className="text-xs text-gray-500 dark:text-slate-500">Scan:</label>
        <select
          value={scanIdx}
          onChange={e => { setScanIdx(Number(e.target.value)); setPkgPage(0); }}
          className={cls.select}
        >
          {scans.map((sc, i) => (
            <option key={sc.id} value={i}>
              {fmtTime(sc.timestamp)} -- {sc.fields?.artifactName ?? 'scan'} ({sc.fields?.packageCount ?? 0} pkgs)
            </option>
          ))}
        </select>
      </div>

      {/* KPIs */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        <StatCard label="Total Packages" value={totalPkgs} />
        <StatCard label="Vulnerable Packages" value={vulnerablePkgs}
          tone={vulnerablePkgs > 0 ? 'danger' : 'success'} />
        <StatCard label="OS Packages" value={osPkgs} />
        <StatCard label="Language Packages" value={langPkgs} />
      </div>

      {/* Search */}
      <div>
        <input
          type="text"
          placeholder="Search packages..."
          value={search}
          onChange={e => { setSearch(e.target.value); setPkgPage(0); }}
          className="px-3 py-1.5 text-sm border border-gray-200 dark:border-slate-700 rounded-lg bg-white dark:bg-slate-800 text-gray-700 dark:text-slate-300 placeholder-gray-400 dark:placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-red-400/50 w-full sm:w-72"
        />
      </div>

      {/* Packages table */}
      {(() => {
        const { paged, total: pTotal, totalPages } = paginate(filtered, pkgPage);
        return (
          <div className={cardCls}>
            <p className={headingCls}>Packages ({filtered.length})</p>
            {filtered.length === 0 ? (
              <p className="text-gray-400 dark:text-slate-600 text-sm py-4">No packages match the current filter.</p>
            ) : (
              <>
                <div className="overflow-x-auto">
                  <table className="w-full text-sm">
                    <thead>
                      <tr className={cls.table.header}>
                        <th className="text-left py-2 px-2">Name</th>
                        <th className="text-left py-2 px-2">Version</th>
                        <th className="text-left py-2 px-2">Type</th>
                        <th className="text-left py-2 px-2">Class</th>
                        <th className="text-left py-2 px-2">Licenses</th>
                        <th className="text-left py-2 px-2">Vulnerabilities</th>
                      </tr>
                    </thead>
                    <tbody>
                      {paged.map((p: Package, i: number) => {
                        const pv = pkgVulnMap[p.name];
                        const maxVulnForBar = 20;
                        return (
                          <tr key={`${p.name}-${p.version}-${i}`} className={cls.table.row}>
                            <td className="py-1.5 px-2 text-xs font-mono text-gray-700 dark:text-slate-300">{p.name}</td>
                            <td className="py-1.5 px-2 text-xs font-mono text-gray-500 dark:text-slate-400">{p.version || '--'}</td>
                            <td className="py-1.5 px-2 text-xs text-gray-500 dark:text-slate-400">{p.type || '--'}</td>
                            <td className="py-1.5 px-2 text-xs">
                              <span className={`px-1.5 py-0.5 rounded text-[10px] font-medium ${
                                p.class === 'os-pkgs'
                                  ? 'bg-blue-100 text-blue-700 dark:bg-blue-900/40 dark:text-blue-300'
                                  : p.class === 'lang-pkgs'
                                    ? 'bg-purple-100 text-purple-700 dark:bg-purple-900/40 dark:text-purple-300'
                                    : 'bg-gray-100 text-gray-600 dark:bg-slate-800 dark:text-slate-400'
                              }`}>
                                {p.class === 'os-pkgs' ? 'OS' : p.class === 'lang-pkgs' ? 'Lang' : p.class || '--'}
                              </span>
                            </td>
                            <td className="py-1.5 px-2 text-xs text-gray-500 dark:text-slate-400">
                              {p.licenses?.length ? p.licenses.join(', ') : '--'}
                            </td>
                            <td className="py-1.5 px-2">
                              {pv ? (
                                <div className="flex items-center gap-2">
                                  <span className="text-xs font-semibold text-gray-700 dark:text-slate-300 w-6 text-right">{pv.total}</span>
                                  <div className="flex h-2 rounded overflow-hidden w-24 bg-gray-100 dark:bg-slate-800">
                                    {(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'] as const).map(sev => {
                                      const count = pv[sev];
                                      if (!count) return null;
                                      const widthPct = Math.max(4, (count / maxVulnForBar) * 100);
                                      return (
                                        <div
                                          key={sev}
                                          className="h-full"
                                          style={{ width: widthPct + '%', backgroundColor: SEVERITY_MINI_COLORS[sev] }}
                                          title={`${sev}: ${count}`}
                                        />
                                      );
                                    })}
                                  </div>
                                </div>
                              ) : (
                                <span className="text-xs text-gray-300 dark:text-slate-600">0</span>
                              )}
                            </td>
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                </div>
                <Pagination page={pkgPage} totalPages={totalPages} total={pTotal} onPageChange={setPkgPage} />
              </>
            )}
          </div>
        );
      })()}
    </div>
  );
}

function PackagesContent() {
  const { filter: f } = useFilter();
  return (
    <ScansProvider filter={{
      projectName: f.projectName || undefined,
      status:      f.status      || undefined,
      limit:       Number(f.limit) || 50,
    }}>
      <Packages />
    </ScansProvider>
  );
}

export default function PackagesPage() {
  return <Suspense fallback={<p className="text-gray-500 text-sm p-4">Loading...</p>}><PackagesContent /></Suspense>;
}