export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'NONE' | 'UNKNOWN'

export interface Finding {
  id: string
  cveId: string
  severity: Severity
  assetName?: string
  assetType?: string
  packageName?: string
  installedVersion?: string
  fixedVersion?: string
  account?: string
  region?: string
  description?: string
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
  packageName?: string
  installedVersion?: string
  fixedVersion?: string
  account?: string
  region?: string
  description?: string
}

export interface Upload {
  id: string
  fileName: string
  fileSize: number
  rowCount: number
  uploadedAt: Date
  columns: string[]
  mapping: ColumnMapping
}
