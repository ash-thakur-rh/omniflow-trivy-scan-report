'use client';

import { useState, useMemo, Suspense } from 'react';
import { ScansProvider, useScans } from '@/components/ScansProvider';
import { Pagination, paginate } from '@/components/Pagination';
import { useFilter, cls } from '@agnistack/omniflow-ui';
import { SeverityBadge, StatusBadge } from '@/components/SeverityBadge';
import type { Vulnerability } from '@/lib/api';

function fmtTime(iso: string) {
  return new Date(iso).toLocaleString('en-US', { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
}
function fmtDate(iso: string) {
  if (!iso) return '--';
  return new Date(iso).toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: 'numeric' });
}

const SEVERITY_ORDER: Record<string, number> = {
  CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, UNKNOWN: 4,
};

function Vulnerabilities() {
  const { scans, isLoading } = useScans();
  const [scanIdx, setScanIdx] = useState(0);
  const [search, setSearch] = useState('');
  const [severityFilter, setSeverityFilter] = useState('ALL');
  const [vulnPage, setVulnPage] = useState(0);
  const [expandedId, setExpandedId] = useState<string | null>(null);

  if (isLoading) return <p className="text-gray-500 dark:text-slate-500 text-sm">Loading...</p>;
  if (!scans.length) return <p className="text-gray-500 dark:text-slate-500 text-sm">No scans ingested yet.</p>;

  const scan = scans[scanIdx];
  const vulns = scan?.fields?.vulnerabilities ?? [];

  const filtered = useMemo(() => {
    let result = [...vulns];

    // Severity filter
    if (severityFilter !== 'ALL') {
      result = result.filter(v => v.severity.toUpperCase() === severityFilter);
    }

    // Search filter
    if (search.trim()) {
      const q = search.toLowerCase();
      result = result.filter(v =>
        v.vulnId.toLowerCase().includes(q) ||
        v.pkgName.toLowerCase().includes(q) ||
        v.title.toLowerCase().includes(q)
      );
    }

    // Sort by severity
    result.sort((a, b) =>
      (SEVERITY_ORDER[a.severity.toUpperCase()] ?? 99) - (SEVERITY_ORDER[b.severity.toUpperCase()] ?? 99)
    );

    return result;
  }, [vulns, severityFilter, search]);

  const severityButtons = ['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];

  const SEVERITY_BTN_ACTIVE: Record<string, string> = {
    ALL:      'bg-gray-800 text-white dark:bg-slate-200 dark:text-slate-900',
    CRITICAL: 'bg-red-900 text-red-100',
    HIGH:     'bg-red-600 text-white',
    MEDIUM:   'bg-orange-500 text-white',
    LOW:      'bg-yellow-500 text-white',
  };

  const cardCls    = cls.card + ' p-4';
  const headingCls = cls.heading + ' mb-3';

  return (
    <div className="max-w-6xl space-y-6">
      {/* Scan selector */}
      <div className="flex items-center gap-3 flex-wrap">
        <label className="text-xs text-gray-500 dark:text-slate-500">Scan:</label>
        <select
          value={scanIdx}
          onChange={e => { setScanIdx(Number(e.target.value)); setVulnPage(0); setExpandedId(null); }}
          className={cls.select}
        >
          {scans.map((sc, i) => (
            <option key={sc.id} value={i}>
              {fmtTime(sc.timestamp)} -- {sc.fields?.artifactName ?? 'scan'} ({sc.fields?.totalVulns ?? 0} vulns)
            </option>
          ))}
        </select>
      </div>

      {/* Search and severity filters */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center gap-3">
        <input
          type="text"
          placeholder="Search CVE ID, package, or title..."
          value={search}
          onChange={e => { setSearch(e.target.value); setVulnPage(0); }}
          className="px-3 py-1.5 text-sm border border-gray-200 dark:border-slate-700 rounded-lg bg-white dark:bg-slate-800 text-gray-700 dark:text-slate-300 placeholder-gray-400 dark:placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-red-400/50 w-full sm:w-72"
        />
        <div className="flex gap-1">
          {severityButtons.map(sev => (
            <button
              key={sev}
              onClick={() => { setSeverityFilter(sev); setVulnPage(0); }}
              className={`px-3 py-1 text-xs rounded-md transition-colors ${
                severityFilter === sev
                  ? SEVERITY_BTN_ACTIVE[sev]
                  : 'bg-gray-100 dark:bg-slate-800 text-gray-600 dark:text-slate-400 hover:bg-gray-200 dark:hover:bg-slate-700'
              }`}
            >
              {sev === 'ALL' ? `All (${vulns.length})` : `${sev} (${vulns.filter(v => v.severity.toUpperCase() === sev).length})`}
            </button>
          ))}
        </div>
      </div>

      {/* Vulnerabilities table */}
      {(() => {
        const { paged, total: vTotal, totalPages } = paginate(filtered, vulnPage);
        return (
          <div className={cardCls}>
            <p className={headingCls}>
              Vulnerabilities ({filtered.length})
              {search && <span className="text-gray-400 dark:text-slate-600 font-normal"> matching &ldquo;{search}&rdquo;</span>}
            </p>
            {filtered.length === 0 ? (
              <p className="text-green-600 dark:text-green-400 text-sm py-4">No vulnerabilities match the current filter.</p>
            ) : (
              <>
                <div className="overflow-x-auto">
                  <table className="w-full text-sm">
                    <thead>
                      <tr className={cls.table.header}>
                        <th className="text-left py-2 px-2 w-6"></th>
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
                      {paged.map((v: Vulnerability) => {
                        const isExpanded = expandedId === v.vulnId + v.pkgName;
                        return (
                          <>
                            <tr
                              key={v.vulnId + v.pkgName}
                              className={`${cls.table.row} cursor-pointer`}
                              onClick={() => setExpandedId(isExpanded ? null : v.vulnId + v.pkgName)}
                            >
                              <td className="py-1.5 px-2 text-gray-400 dark:text-slate-600 text-xs">
                                {isExpanded ? '▼' : '▶'}
                              </td>
                              <td className="py-1.5 px-2 font-mono text-xs">
                                {v.primaryUrl ? (
                                  <a href={v.primaryUrl} target="_blank" rel="noopener noreferrer"
                                    className="text-blue-600 dark:text-blue-400 hover:underline"
                                    onClick={e => e.stopPropagation()}>
                                    {v.vulnId}
                                  </a>
                                ) : v.vulnId}
                              </td>
                              <td className="py-1.5 px-2"><SeverityBadge severity={v.severity} /></td>
                              <td className="py-1.5 px-2 text-xs text-gray-700 dark:text-slate-300">{v.pkgName}</td>
                              <td className="py-1.5 px-2 font-mono text-xs text-gray-500 dark:text-slate-400">{v.installedVersion || '--'}</td>
                              <td className="py-1.5 px-2 font-mono text-xs text-green-600 dark:text-green-400">{v.fixedVersion || '--'}</td>
                              <td className="py-1.5 px-2"><StatusBadge status={v.status} /></td>
                              <td className="py-1.5 px-2 text-xs text-gray-600 dark:text-slate-400 max-w-[300px] truncate" title={v.title}>
                                {v.title || '--'}
                              </td>
                            </tr>
                            {isExpanded && (
                              <tr key={v.vulnId + v.pkgName + '-detail'} className="bg-gray-50 dark:bg-slate-900/50">
                                <td colSpan={8} className="py-3 px-4">
                                  <div className="space-y-3 text-xs">
                                    {v.description && (
                                      <div>
                                        <p className="font-semibold text-gray-700 dark:text-slate-300 mb-1">Description</p>
                                        <p className="text-gray-600 dark:text-slate-400 leading-relaxed">{v.description}</p>
                                      </div>
                                    )}
                                    <div className="flex flex-wrap gap-6">
                                      {v.cvssScore > 0 && (
                                        <div>
                                          <p className="font-semibold text-gray-700 dark:text-slate-300 mb-1">CVSS Score</p>
                                          <p className={`text-lg font-bold ${
                                            v.cvssScore >= 9 ? 'text-red-700 dark:text-red-400' :
                                            v.cvssScore >= 7 ? 'text-red-600 dark:text-red-400' :
                                            v.cvssScore >= 4 ? 'text-orange-600 dark:text-orange-400' :
                                            'text-yellow-600 dark:text-yellow-400'
                                          }`}>
                                            {v.cvssScore.toFixed(1)}
                                          </p>
                                        </div>
                                      )}
                                      {v.cweIds.length > 0 && (
                                        <div>
                                          <p className="font-semibold text-gray-700 dark:text-slate-300 mb-1">CWE IDs</p>
                                          <div className="flex gap-1 flex-wrap">
                                            {v.cweIds.map(cwe => (
                                              <span key={cwe} className="px-1.5 py-0.5 rounded bg-slate-100 dark:bg-slate-800 text-slate-600 dark:text-slate-400 border border-slate-200 dark:border-slate-700">
                                                {cwe}
                                              </span>
                                            ))}
                                          </div>
                                        </div>
                                      )}
                                      {v.publishedDate && (
                                        <div>
                                          <p className="font-semibold text-gray-700 dark:text-slate-300 mb-1">Published</p>
                                          <p className="text-gray-500 dark:text-slate-400">{fmtDate(v.publishedDate)}</p>
                                        </div>
                                      )}
                                    </div>
                                    {v.references.length > 0 && (
                                      <div>
                                        <p className="font-semibold text-gray-700 dark:text-slate-300 mb-1">References</p>
                                        <ul className="space-y-0.5">
                                          {v.references.slice(0, 5).map((ref, i) => (
                                            <li key={i}>
                                              <a href={ref} target="_blank" rel="noopener noreferrer"
                                                className="text-blue-600 dark:text-blue-400 hover:underline break-all">
                                                {ref}
                                              </a>
                                            </li>
                                          ))}
                                          {v.references.length > 5 && (
                                            <li className="text-gray-400 dark:text-slate-600">
                                              ...and {v.references.length - 5} more
                                            </li>
                                          )}
                                        </ul>
                                      </div>
                                    )}
                                  </div>
                                </td>
                              </tr>
                            )}
                          </>
                        );
                      })}
                    </tbody>
                  </table>
                </div>
                <Pagination page={vulnPage} totalPages={totalPages} total={vTotal} onPageChange={setVulnPage} />
              </>
            )}
          </div>
        );
      })()}
    </div>
  );
}

function VulnerabilitiesContent() {
  const { filter: f } = useFilter();
  return (
    <ScansProvider filter={{
      projectName: f.projectName || undefined,
      status:      f.status      || undefined,
      limit:       Number(f.limit) || 50,
    }}>
      <Vulnerabilities />
    </ScansProvider>
  );
}

export default function VulnerabilitiesPage() {
  return <Suspense fallback={<p className="text-gray-500 text-sm p-4">Loading...</p>}><VulnerabilitiesContent /></Suspense>;
}