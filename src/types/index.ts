export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'NONE' | 'UNKNOWN'

/** Canonical severity order from most to least critical. */
export const SEVERITY_ORDER: Record<Severity, number> = {
  CRITICAL: 0,
  HIGH: 1,
  MEDIUM: 2,
  LOW: 3,
  NONE: 4,
  UNKNOWN: 5,
}

/** Sorted list of all severities in canonical order. */
export const ORDERED_SEVERITIES: Severity[] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'NONE', 'UNKNOWN']

/** Comparator: sort by severity, most severe first. */
export function compareSeverity(a: Severity, b: Severity): number {
  return SEVERITY_ORDER[a] - SEVERITY_ORDER[b]
}

export interface Finding {
  id: string
  cveId: string
  severity: Severity
  assetName?: string
  assetType?: string
  arn?: string
  packageName?: string
  installedVersion?: string
  fixedVersion?: string
  account?: string       // Account ID / identifier
  accountName?: string   // Human-readable account label / alias
  region?: string
  description?: string
  sla?: string           // SLA due date or remediation deadline
  sourceFile: string
  raw: Record<string, unknown>
}

export interface CVEGroup {
  cveId: string
  severity: Severity
  findings: Finding[]
  affectedAssets: number
  packages: string[]
  description?: string
}

export interface DashboardMetrics {
  totalFindings: number
  uniqueCVEs: number
  criticalFindings: number
  affectedAssets: number
  severityCounts: Record<Severity, number>
  topCVEs: Array<{ cveId: string; count: number; severity: Severity }>
  topAssets: Array<{ asset: string; count: number }>
}

export interface ColumnMapping {
  cveId?: string
  severity?: string
  assetName?: string
  assetType?: string
  arn?: string
  packageName?: string
  installedVersion?: string
  fixedVersion?: string
  account?: string
  accountName?: string
  region?: string
  description?: string
  sla?: string
}

export interface Upload {
  id: string
  fileName: string
  fileSize: number
  rowCount: number
  uploadedAt: Date
  columns: string[]
  mapping: ColumnMapping
  rawRows: Record<string, unknown>[]  // retained for post-upload column remapping
}

// ── NVD / CVE enrichment ────────────────────────────────────────────────────

export interface NVDReference {
  url: string
  source?: string
  tags?: string[]
}

export interface NVDCVEData {
  cveId: string
  description: string
  cvssV3Score?: number
  cvssV3Vector?: string
  cvssV3BaseSeverity?: string
  cvssV2Score?: number
  exploitabilityScore?: number
  impactScore?: number
  cwes: string[]
  references: NVDReference[]
  publishedDate: string
  lastModifiedDate: string
  fetchedAt: number
}

// ── Analytics ────────────────────────────────────────────────────────────────

export type DimensionKey =
  | 'severity'
  | 'account'
  | 'region'
  | 'packageName'
  | 'assetType'
  | 'assetName'
  | 'sourceFile'
  | 'cveYear'
  | 'cveId'
  | 'sla'

export type MetricKey = 'findings' | 'uniqueCVEs' | 'affectedAssets' | 'fixableFindings'

export type ChartType = 'bar' | 'pie' | 'scatter' | 'treemap'

export interface AnalyticsFilters {
  severities: Severity[]
  accounts: string[]
  regions: string[]
  assetTypes: string[]
  hasFix: boolean | null
  cvssMin: number
  cvssMax: number
}

export interface AnalyticsConfig {
  chartType: ChartType
  groupBy: DimensionKey
  stackBy?: DimensionKey
  metric: MetricKey
  filters: AnalyticsFilters
  topN: number
}

export interface AnalyticsPreset {
  id: string
  name: string
  description?: string
  config: AnalyticsConfig
  createdAt: number
}

