'use client';

import { createContext, useContext } from 'react';
import useSWR from 'swr';
import { ScanRecord } from '@/lib/api';

const BASE = process.env.NEXT_PUBLIC_API_URL ?? '';
const fetcher = (url: string) => fetch(BASE + url).then(r => r.ok ? r.json() : []);

export interface ScanFilter {
  projectName?: string;
  status?: string;
  limit?: number;
}

interface ScansContext { scans: ScanRecord[]; isLoading: boolean; }
const Ctx = createContext<ScansContext>({ scans: [], isLoading: true });

export function ScansProvider({
  children,
  filter = {},
  limit,
}: { children: React.ReactNode; filter?: ScanFilter; limit?: number }) {
  const params = new URLSearchParams({
    type: 'trivy-scan-report',
    size: String(filter.limit ?? limit ?? 50),
  });
  if (filter.projectName) params.set('projectName', filter.projectName);
  if (filter.status)      params.set('status',      filter.status);

  const { data, isLoading } = useSWR<{ entries: ScanRecord[] }>(
    `/api/v1/analytics/builds?${params}`,
    fetcher,
    { refreshInterval: 30_000 },
  );
  return <Ctx.Provider value={{ scans: data?.entries ?? [], isLoading }}>{children}</Ctx.Provider>;
}

export const useScans = () => useContext(Ctx);