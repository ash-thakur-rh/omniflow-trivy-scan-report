// The OmniFlow backend URL. Defaults to same origin in production (assets
// are served by the OmniFlow host at /api/plugins/trivy-scan-report/ui).
const BASE = process.env.NEXT_PUBLIC_API_URL ?? '';

async function get<T>(path: string): Promise<T> {
  const res = await fetch(BASE + path);
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
  return res.json() as Promise<T>;
}

// ── Types ─────────────────────────────────────────────────────────────────

export interface Vulnerability {
  vulnId:           string;
  pkgName:          string;
  installedVersion: string;
  fixedVersion:     string;
  severity:         string;
  status:           string;
  title:            string;
  description:      string;
  cvssScore:        number;
  cweIds:           string[];
  primaryUrl:       string;
  references:       string[];
  publishedDate:    string;
  lastModifiedDate: string;
  target:           string;
  class:            string;
  type:             string;
}

export interface Package {
  name:     string;
  version:  string;
  arch:     string;
  type:     string;
  class:    string;
  target:   string;
  licenses: string[];
}

export interface SeverityCounts {
  CRITICAL: number;
  HIGH:     number;
  MEDIUM:   number;
  LOW:      number;
  UNKNOWN:  number;
}

export interface ScanFields {
  artifactName:          string;
  artifactType:          string;
  osFamily:              string;
  osName:                string;
  imageId:               string;
  repoTags:              string[];
  vulnerabilities:       Vulnerability[];
  packages:              Package[];
  totalVulns:            number;
  severityCounts:        SeverityCounts;
  fixableCount:          number;
  packageCount:          number;
  vulnerablePackageCount: number;
  healthy:               boolean;
}

export interface ScanRecord {
  id:        string;
  type:      string;
  timestamp: string;
  fields:    ScanFields;
}

// ── API calls ─────────────────────────────────────────────────────────────

export const fetchScans = (limit = 50) =>
  get<ScanRecord[]>(`/api/v1/analytics/builds?type=trivy-scan-report&limit=${limit}`);