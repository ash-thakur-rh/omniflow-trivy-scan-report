'use client';

const SEVERITY_STYLES: Record<string, string> = {
  CRITICAL: 'bg-red-950/80 text-red-200 border-red-800 dark:bg-red-950 dark:text-red-300 dark:border-red-900',
  HIGH:     'bg-red-100 text-red-700 border-red-200 dark:bg-red-900/40 dark:text-red-300 dark:border-red-800',
  MEDIUM:   'bg-orange-100 text-orange-700 border-orange-200 dark:bg-orange-900/40 dark:text-orange-300 dark:border-orange-800',
  LOW:      'bg-yellow-100 text-yellow-700 border-yellow-200 dark:bg-yellow-900/40 dark:text-yellow-300 dark:border-yellow-800',
  UNKNOWN:  'bg-slate-100 text-slate-600 border-slate-200 dark:bg-slate-800 dark:text-slate-400 dark:border-slate-700',
};

const STATUS_STYLES: Record<string, string> = {
  fixed:         'bg-green-100 text-green-700 border-green-200 dark:bg-green-900/40 dark:text-green-300 dark:border-green-800',
  affected:      'bg-red-100 text-red-700 border-red-200 dark:bg-red-900/40 dark:text-red-300 dark:border-red-800',
  will_not_fix:  'bg-slate-100 text-slate-600 border-slate-200 dark:bg-slate-800 dark:text-slate-400 dark:border-slate-700',
};

export function SeverityBadge({ severity }: { severity: string }) {
  const s = severity.toUpperCase();
  return (
    <span className={`text-[10px] font-semibold px-1.5 py-0.5 rounded border ${SEVERITY_STYLES[s] ?? SEVERITY_STYLES.UNKNOWN}`}>
      {s}
    </span>
  );
}

export function StatusBadge({ status }: { status: string }) {
  const s = status.toLowerCase();
  const label = s === 'will_not_fix' ? 'WON\'T FIX' : s.toUpperCase();
  return (
    <span className={`text-[10px] font-semibold px-1.5 py-0.5 rounded border ${STATUS_STYLES[s] ?? STATUS_STYLES.affected}`}>
      {label}
    </span>
  );
}