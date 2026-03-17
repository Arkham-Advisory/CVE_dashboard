import { create } from 'zustand'
import type { Finding, CVEGroup, DashboardMetrics, Upload, ColumnMapping, Severity } from '@/types'
import { SEVERITY_ORDER } from '@/types'
import { rowsToFindings } from '@/lib/parser'

interface AppState {
  uploads: Upload[]
  findings: Finding[]
  cveGroups: CVEGroup[]
  metrics: DashboardMetrics
  columnMapping: ColumnMapping
  selectedCVE: CVEGroup | null

  // Actions
  addFindings: (findings: Finding[], upload: Upload) => void
  clearAll: () => void
  setSelectedCVE: (cve: CVEGroup | null) => void
  updateColumnMapping: (mapping: ColumnMapping) => void
  remapUpload: (uploadId: string, newMapping: ColumnMapping) => void
}

function computeMetrics(findings: Finding[]): DashboardMetrics {
  const severityCounts: Record<Severity, number> = {
    CRITICAL: 0,
    HIGH: 0,
    MEDIUM: 0,
    LOW: 0,
    NONE: 0,
    UNKNOWN: 0,
  }

  const cveCountMap = new Map<string, { count: number; severity: Severity }>()
  const assetCountMap = new Map<string, number>()
  const assetSet = new Set<string>()

  for (const f of findings) {
    severityCounts[f.severity] = (severityCounts[f.severity] ?? 0) + 1

    const existing = cveCountMap.get(f.cveId)
    if (!existing || SEVERITY_ORDER[f.severity] < SEVERITY_ORDER[existing.severity]) {
      cveCountMap.set(f.cveId, { count: (existing?.count ?? 0) + 1, severity: f.severity })
    } else {
      cveCountMap.set(f.cveId, { count: existing.count + 1, severity: existing.severity })
    }

    if (f.assetName) {
      assetSet.add(f.assetName)
      assetCountMap.set(f.assetName, (assetCountMap.get(f.assetName) ?? 0) + 1)
    }
  }

  const topCVEs = Array.from(cveCountMap.entries())
    .map(([cveId, { count, severity }]) => ({ cveId, count, severity }))
    .sort((a, b) => {
      if (SEVERITY_ORDER[a.severity] !== SEVERITY_ORDER[b.severity]) {
        return SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity]
      }
      return b.count - a.count
    })
    .slice(0, 10)

  const topAssets = Array.from(assetCountMap.entries())
    .map(([asset, count]) => ({ asset, count }))
    .sort((a, b) => b.count - a.count)
    .slice(0, 10)

  return {
    totalFindings: findings.length,
    uniqueCVEs: cveCountMap.size,
    criticalFindings: severityCounts.CRITICAL,
    affectedAssets: assetSet.size,
    severityCounts,
    topCVEs,
    topAssets,
  }
}

function groupByCVE(findings: Finding[]): CVEGroup[] {
  const map = new Map<string, CVEGroup>()

  for (const f of findings) {
    const existing = map.get(f.cveId)
    if (existing) {
      existing.findings.push(f)
      if (f.assetName && !existing.packages.includes(f.assetName)) {
        // Count unique assets
      }
      if (f.packageName && !existing.packages.includes(f.packageName)) {
        existing.packages.push(f.packageName)
      }
      if (SEVERITY_ORDER[f.severity] < SEVERITY_ORDER[existing.severity]) {
        existing.severity = f.severity
      }
    } else {
      map.set(f.cveId, {
        cveId: f.cveId,
        severity: f.severity,
        findings: [f],
        affectedAssets: 0,
        packages: f.packageName ? [f.packageName] : [],
        description: f.description,
      })
    }
  }

  // Compute affectedAssets
  for (const group of map.values()) {
    const assets = new Set(group.findings.map((f) => f.assetName).filter(Boolean))
    group.affectedAssets = assets.size
  }

  return Array.from(map.values()).sort(
    (a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity],
  )
}

const emptyMetrics: DashboardMetrics = {
  totalFindings: 0,
  uniqueCVEs: 0,
  criticalFindings: 0,
  affectedAssets: 0,
  severityCounts: { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, NONE: 0, UNKNOWN: 0 },
  topCVEs: [],
  topAssets: [],
}

export const useAppStore = create<AppState>()((set, get) => ({
  uploads: [],
  findings: [],
  cveGroups: [],
  metrics: emptyMetrics,
  columnMapping: {},
  selectedCVE: null,

  addFindings: (newFindings, upload) => {
    const allFindings = [...get().findings, ...newFindings]
    set({
      findings: allFindings,
      cveGroups: groupByCVE(allFindings),
      metrics: computeMetrics(allFindings),
      uploads: [...get().uploads, upload],
    })
  },

  clearAll: () =>
    set({
      uploads: [],
      findings: [],
      cveGroups: [],
      metrics: emptyMetrics,
    }),

  setSelectedCVE: (cve) => set({ selectedCVE: cve }),

  updateColumnMapping: (mapping) => set({ columnMapping: mapping }),

  remapUpload: (uploadId, newMapping) => {
    const { uploads, findings } = get()
    const upload = uploads.find((u) => u.id === uploadId)
    if (!upload) return

    // Replace findings from this source with freshly derived ones
    const otherFindings = findings.filter((f) => f.sourceFile !== upload.fileName)
    const remapped = rowsToFindings(upload.rawRows, newMapping, upload.fileName)
    const allFindings = [...otherFindings, ...remapped]

    set({
      uploads: uploads.map((u) => (u.id === uploadId ? { ...u, mapping: newMapping } : u)),
      findings: allFindings,
      cveGroups: groupByCVE(allFindings),
      metrics: computeMetrics(allFindings),
    })
  },
}))
