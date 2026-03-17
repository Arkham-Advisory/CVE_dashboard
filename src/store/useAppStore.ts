import { create } from 'zustand'
import type { Finding, CVEGroup, DashboardMetrics, Upload, ColumnMapping, Severity } from '@/types'
import { SEVERITY_ORDER } from '@/types'
import { rowsToFindings } from '@/lib/parser'
import { computeRiskScore, getPriorityLabel, computeSecurityScore } from '@/lib/riskScore'
import { buildDemoFindings, buildDemoUpload } from '@/lib/demoData'

interface AppState {
  uploads: Upload[]
  findings: Finding[]
  cveGroups: CVEGroup[]
  metrics: DashboardMetrics
  columnMapping: ColumnMapping
  selectedCVE: CVEGroup | null
  isDemoMode: boolean

  // Actions
  addFindings: (findings: Finding[], upload: Upload) => void
  clearAll: () => void
  setSelectedCVE: (cve: CVEGroup | null) => void
  updateColumnMapping: (mapping: ColumnMapping) => void
  remapUpload: (uploadId: string, newMapping: ColumnMapping) => void
  loadDemo: () => void
}

function computeMetrics(findings: Finding[]): DashboardMetrics {
  const severityCounts: Record<Severity, number> = {
    CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, NONE: 0, UNKNOWN: 0,
  }

  type CVEBucket = { count: number; severity: Severity; assets: Set<string>; exploitable: boolean; fixAvailable: boolean; riskScore: number }
  const cveCountMap = new Map<string, CVEBucket>()
  const assetCountMap = new Map<string, number>()
  const assetSeverityMap = new Map<string, Record<Severity, number>>()
  const assetSet = new Set<string>()

  for (const f of findings) {
    severityCounts[f.severity] = (severityCounts[f.severity] ?? 0) + 1

    const existing = cveCountMap.get(f.cveId)
    const isExploitable = !!(f.exploitKnown || f.exploitAvailable)
    const hasFix = !!f.fixedVersion
    const rScore = f.riskScore ?? 0

    if (!existing) {
      const assets = new Set<string>()
      if (f.assetName) assets.add(f.assetName)
      cveCountMap.set(f.cveId, { count: 1, severity: f.severity, assets, exploitable: isExploitable, fixAvailable: hasFix, riskScore: rScore })
    } else {
      if (f.assetName) existing.assets.add(f.assetName)
      existing.count += 1
      existing.exploitable = existing.exploitable || isExploitable
      existing.fixAvailable = existing.fixAvailable || hasFix
      existing.riskScore = Math.max(existing.riskScore, rScore)
      if (SEVERITY_ORDER[f.severity] < SEVERITY_ORDER[existing.severity]) existing.severity = f.severity
    }

    if (f.assetName) {
      assetSet.add(f.assetName)
      assetCountMap.set(f.assetName, (assetCountMap.get(f.assetName) ?? 0) + 1)
      const sev = assetSeverityMap.get(f.assetName) ?? { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, NONE: 0, UNKNOWN: 0 }
      sev[f.severity] = (sev[f.severity] ?? 0) + 1
      assetSeverityMap.set(f.assetName, sev)
    }
  }

  const topCVEs = Array.from(cveCountMap.entries())
    .map(([cveId, { count, severity, assets }]) => ({ cveId, count, severity, affectedAssets: assets.size }))
    .sort((a, b) => {
      if (SEVERITY_ORDER[a.severity] !== SEVERITY_ORDER[b.severity])
        return SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity]
      return b.count - a.count
    })
    .slice(0, 10)

  const topAssets = Array.from(assetCountMap.entries())
    .map(([asset, count]) => ({
      asset,
      count,
      bySeverity: assetSeverityMap.get(asset) ?? { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, NONE: 0, UNKNOWN: 0 },
    }))
    .sort((a, b) => b.count - a.count)
    .slice(0, 10)

  const topRemediationTargets = Array.from(cveCountMap.entries())
    .map(([cveId, v]) => ({
      cveId, severity: v.severity, affectedAssets: v.assets.size,
      fixAvailable: v.fixAvailable, riskScore: v.riskScore, exploitable: v.exploitable,
    }))
    .filter((t) => t.severity === 'CRITICAL' || t.severity === 'HIGH' || t.exploitable || t.fixAvailable)
    .sort((a, b) => (b.riskScore * (b.affectedAssets || 1)) - (a.riskScore * (a.affectedAssets || 1)))
    .slice(0, 5)

  const blastRadius = Array.from(cveCountMap.entries())
    .map(([cveId, v]) => ({ cveId, affectedAssets: v.assets.size, severity: v.severity }))
    .sort((a, b) => b.affectedAssets - a.affectedAssets)[0] ?? null

  return {
    totalFindings: findings.length,
    uniqueCVEs: cveCountMap.size,
    criticalFindings: severityCounts.CRITICAL,
    affectedAssets: assetSet.size,
    severityCounts,
    topCVEs,
    topAssets,
    securityScore: computeSecurityScore(findings),
    exploitableFindings: findings.filter((f) => f.exploitKnown || f.exploitAvailable).length,
    fixableFindings: findings.filter((f) => !!f.fixedVersion).length,
    topRemediationTargets,
    blastRadius,
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
  totalFindings: 0, uniqueCVEs: 0, criticalFindings: 0, affectedAssets: 0,
  severityCounts: { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, NONE: 0, UNKNOWN: 0 },
  topCVEs: [], topAssets: [],
  securityScore: 100, exploitableFindings: 0, fixableFindings: 0,
  topRemediationTargets: [], blastRadius: null,
}

/** Enrich findings with risk scores and priority labels, using asset counts per CVE. */
function enrichFindings(findings: Finding[]): Finding[] {
  const assetCountByCVE = new Map<string, number>()
  for (const f of findings) {
    const assets = new Set(findings.filter((x) => x.cveId === f.cveId).map((x) => x.assetName).filter(Boolean))
    assetCountByCVE.set(f.cveId, assets.size)
  }
  return findings.map((f) => ({
    ...f,
    riskScore: computeRiskScore(f, assetCountByCVE.get(f.cveId) ?? 1),
    priorityLabel: getPriorityLabel(f),
  }))
}

export const useAppStore = create<AppState>()((set, get) => ({
  uploads: [],
  findings: [],
  cveGroups: [],
  metrics: emptyMetrics,
  columnMapping: {},
  selectedCVE: null,
  isDemoMode: false,

  addFindings: (newFindings, upload) => {
    const raw = [...get().findings, ...newFindings]
    const allFindings = enrichFindings(raw)
    set({
      findings: allFindings,
      cveGroups: groupByCVE(allFindings),
      metrics: computeMetrics(allFindings),
      uploads: [...get().uploads, upload],
    })
  },

  clearAll: () => set({ uploads: [], findings: [], cveGroups: [], metrics: emptyMetrics, isDemoMode: false }),

  setSelectedCVE: (cve) => set({ selectedCVE: cve }),

  updateColumnMapping: (mapping) => set({ columnMapping: mapping }),

  loadDemo: () => {
    const demoFindings = buildDemoFindings()
    const demoUpload = buildDemoUpload()
    const allFindings = enrichFindings(demoFindings)
    set({
      findings: allFindings,
      cveGroups: groupByCVE(allFindings),
      metrics: computeMetrics(allFindings),
      uploads: [demoUpload],
      isDemoMode: true,
    })
  },

  remapUpload: (uploadId, newMapping) => {
    const { uploads, findings } = get()
    const upload = uploads.find((u) => u.id === uploadId)
    if (!upload) return

    // Replace findings from this source with freshly derived ones
    const otherFindings = findings.filter((f) => f.sourceFile !== upload.fileName)
    const remapped = rowsToFindings(upload.rawRows, newMapping, upload.fileName)
    const allFindings = enrichFindings([...otherFindings, ...remapped])

    set({
      uploads: uploads.map((u) => (u.id === uploadId ? { ...u, mapping: newMapping } : u)),
      findings: allFindings,
      cveGroups: groupByCVE(allFindings),
      metrics: computeMetrics(allFindings),
    })
  },
}))
