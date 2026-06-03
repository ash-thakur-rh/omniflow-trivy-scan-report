'use client';

import { useState, useMemo, Suspense } from 'react';
import { ScansProvider, useScans } from '@/components/ScansProvider';
import { Pagination, paginate } from '@/components/Pagination';
import { useFilter, StatCard, cls } from '@agnistack/omniflow-ui';
import { SeverityBadge, StatusBadge } from '@/components/SeverityBadge';
import type { Vulnerability } from '@/lib/api';

function fmtTime(iso: string) {
  return new Date(iso).toLocaleString('en-US', { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
}

function Compare() {
  const { scans, isLoading } = useScans();
  const [idxA, setIdxA] = useState<string>('');
  const [idxB, setIdxB] = useState<string>('');
  const [newPage, setNewPage] = useState(0);
  const [resolvedPage, setResolvedPage] = useState(0);
  const [persistentPage, setPersistentPage] = useState(0);

  if (isLoading) return <p className="text-gray-500 dark:text-slate-500 text-sm">Loading scans...</p>;
  if (scans.length < 2) return <p className="text-gray-500 dark:text-slate-500 text-sm">Need at least 2 scans to compare.</p>;

  const scanA = scans.find(s => s.id === idxA);
  const scanB = scans.find(s => s.id === idxB);

  // Compute comparison
  const comparison = useMemo(() => {
    if (!scanA || !scanB || scanA.id === scanB.id) return null;

    const vulnsA = scanA.fields?.vulnerabilities ?? [];
    const vulnsB = scanB.fields?.vulnerabilities ?? [];

    // Create sets of vuln IDs for comparison
    const setA = new Set(vulnsA.map(v => `${v.vulnId}|${v.pkgName}`));
    const setB = new Set(vulnsB.map(v => `${v.vulnId}|${v.pkgName}`));
    const vulnMapA: Record<string, Vulnerability> = {};
    const vulnMapB: Record<string, Vulnerability> = {};
    vulnsA.forEach(v => { vulnMapA[`${v.vulnId}|${v.pkgName}`] = v; });
    vulnsB.forEach(v => { vulnMapB[`${v.vulnId}|${v.pkgName}`] = v; });

    // Resolved: in A but not in B (good -- vulnerabilities that went away)
    const resolved: Vulnerability[] = [];
    setA.forEach(key => {
      if (!setB.has(key)) resolved.push(vulnMapA[key]);
    });

    // New: in B but not in A (bad -- new vulnerabilities appeared)
    const added: Vulnerability[] = [];
    setB.forEach(key => {
      if (!setA.has(key)) added.push(vulnMapB[key]);
    });

    // Persistent: in both A and B
    const persistent: Vulnerability[] = [];
    setA.forEach(key => {
      if (setB.has(key)) persistent.push(vulnMapB[key]);
    });

    const totalDelta = vulnsB.length - vulnsA.length;

    return { resolved, added, persistent, totalDelta };
  }, [scanA, scanB]);

  const SEVERITY_ORDER: Record<string, number> = {
    CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, UNKNOWN: 4,
  };
  const sortBySev = (arr: Vulnerability[]) =>
    [...arr].sort((a, b) => (SEVERITY_ORDER[a.severity.toUpperCase()] ?? 99) - (SEVERITY_ORDER[b.severity.toUpperCase()] ?? 99));

  const cardCls    = cls.card + ' p-4';
  const headingCls = cls.heading + ' mb-3';

  const VulnTable = ({ vulns, page, onPageChange, emptyMsg }: {
    vulns: Vulnerability[];
    page: number;
    onPageChange: (p: number) => void;
    emptyMsg: string;
  }) => {
    const sorted = sortBySev(vulns);
    const { paged, total, totalPages } = paginate(sorted, page);
    if (!total) return <p className="text-sm text-gray-400 dark:text-slate-600 py-2">{emptyMsg}</p>;
    return (
      <>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className={cls.table.header}>
                <th className="text-left py-2 px-2">CVE ID</th>
                <th className="text-left py-2 px-2">Severity</th>
                <th className="text-left py-2 px-2">Package</th>
                <th className="text-left py-2 px-2">Installed</th>
                <th className="text-left py-2 px-2">Fixed</th>
                <th className="text-left py-2 px-2">Status</th>
                <th className="text-left py-2 px-2">Title</th>
              </tr>
            </thead>
            <tbody>
              {paged.map(v => (
                <tr key={v.vulnId + v.pkgName} className={cls.table.row}>
                  <td className="py-1.5 px-2 font-mono text-xs">
                    {v.primaryUrl ? (
                      <a href={v.primaryUrl} target="_blank" rel="noopener noreferrer"
                        className="text-blue-600 dark:text-blue-400 hover:underline">
                        {v.vulnId}
                      </a>
                    ) : v.vulnId}
                  </td>
                  <td className="py-1.5 px-2"><SeverityBadge severity={v.severity} /></td>
                  <td className="py-1.5 px-2 text-xs text-gray-700 dark:text-slate-300">{v.pkgName}</td>
                  <td className="py-1.5 px-2 font-mono text-xs text-gray-500 dark:text-slate-400">{v.installedVersion || '--'}</td>
                  <td className="py-1.5 px-2 font-mono text-xs text-green-600 dark:text-green-400">{v.fixedVersion || '--'}</td>
                  <td className="py-1.5 px-2"><StatusBadge status={v.status} /></td>
                  <td className="py-1.5 px-2 text-xs text-gray-600 dark:text-slate-400 max-w-[250px] truncate" title={v.title}>
                    {v.title || '--'}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <Pagination page={page} totalPages={totalPages} total={total} onPageChange={onPageChange} />
      </>
    );
  };

  return (
    <div className="max-w-6xl space-y-6">
      {/* Selectors */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <div>
          <label className="text-xs text-gray-500 dark:text-slate-500 mb-1 block">Scan A (baseline)</label>
          <select value={idxA} onChange={e => { setIdxA(e.target.value); setNewPage(0); setResolvedPage(0); setPersistentPage(0); }} className={cls.select + ' w-full'}>
            <option value="">Select a scan...</option>
            {scans.map(sc => (
              <option key={sc.id} value={sc.id}>
                {fmtTime(sc.timestamp)} -- {sc.fields?.artifactName ?? 'scan'} ({sc.fields?.totalVulns ?? 0} vulns)
              </option>
            ))}
          </select>
        </div>
        <div>
          <label className="text-xs text-gray-500 dark:text-slate-500 mb-1 block">Scan B (current)</label>
          <select value={idxB} onChange={e => { setIdxB(e.target.value); setNewPage(0); setResolvedPage(0); setPersistentPage(0); }} className={cls.select + ' w-full'}>
            <option value="">Select a scan...</option>
            {scans.map(sc => (
              <option key={sc.id} value={sc.id}>
                {fmtTime(sc.timestamp)} -- {sc.fields?.artifactName ?? 'scan'} ({sc.fields?.totalVulns ?? 0} vulns)
              </option>
            ))}
          </select>
        </div>
      </div>

      {idxA && idxB && idxA === idxB && (
        <p className="text-amber-600 dark:text-amber-400 text-sm">Select two different scans to compare.</p>
      )}

      {comparison && (
        <>
          {/* Summary cards */}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
            <StatCard label="New Vulns" value={comparison.added.length}
              tone={comparison.added.length > 0 ? 'danger' : 'success'} />
            <StatCard label="Resolved Vulns" value={comparison.resolved.length}
              tone={comparison.resolved.length > 0 ? 'success' : 'neutral'} />
            <StatCard label="Persistent Vulns" value={comparison.persistent.length}
              tone={comparison.persistent.length > 0 ? 'warn' : 'success'} />
            <StatCard label="Total Delta" value={(comparison.totalDelta > 0 ? '+' : '') + comparison.totalDelta}
              tone={comparison.totalDelta > 0 ? 'danger' : comparison.totalDelta < 0 ? 'success' : 'neutral'} />
          </div>

          {/* Resolved vulnerabilities (green header -- these went away) */}
          <div className={cardCls}>
            <div className="flex items-center gap-2 mb-3">
              <div className="w-2 h-2 rounded-full bg-green-500"></div>
              <p className={cls.heading}>Resolved Vulnerabilities ({comparison.resolved.length})</p>
              <span className="text-xs text-gray-400 dark:text-slate-600">Present in A, absent in B</span>
            </div>
            <VulnTable
              vulns={comparison.resolved}
              page={resolvedPage}
              onPageChange={setResolvedPage}
              emptyMsg="No resolved vulnerabilities."
            />
          </div>

          {/* Added vulnerabilities (red header -- new risks) */}
          <div className={cardCls}>
            <div className="flex items-center gap-2 mb-3">
              <div className="w-2 h-2 rounded-full bg-red-500"></div>
              <p className={cls.heading}>New Vulnerabilities ({comparison.added.length})</p>
              <span className="text-xs text-gray-400 dark:text-slate-600">Absent in A, present in B</span>
            </div>
            <VulnTable
              vulns={comparison.added}
              page={newPage}
              onPageChange={setNewPage}
              emptyMsg="No new vulnerabilities."
            />
          </div>

          {/* Persistent vulnerabilities */}
          <div className={cardCls}>
            <div className="flex items-center gap-2 mb-3">
              <div className="w-2 h-2 rounded-full bg-amber-500"></div>
              <p className={cls.heading}>Persistent Vulnerabilities ({comparison.persistent.length})</p>
              <span className="text-xs text-gray-400 dark:text-slate-600">Present in both A and B</span>
            </div>
            <VulnTable
              vulns={comparison.persistent}
              page={persistentPage}
              onPageChange={setPersistentPage}
              emptyMsg="No persistent vulnerabilities."
            />
          </div>
        </>
      )}
    </div>
  );
}

function CompareContent() {
  const { filter: f } = useFilter();
  return (
    <ScansProvider filter={{ limit: Number(f.limit) || 50 }}>
      <Compare />
    </ScansProvider>
  );
}

export default function ComparePage() {
  return <Suspense fallback={<p className="text-gray-500 text-sm p-4">Loading...</p>}><CompareContent /></Suspense>;
}