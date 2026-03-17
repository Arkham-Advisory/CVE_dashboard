import type { Finding, RiskPriority, FixStatus, Severity } from '@/types'

// ── Severity weights ─────────────────────────────────────────────────────────

const SEVERITY_WEIGHTS: Record<Severity, number> = {
  CRITICAL: 40,
  HIGH: 30,
  MEDIUM: 20,
  LOW: 10,
  NONE: 5,
  UNKNOWN: 10,
}

/**
 * Compute a risk score (0–100) for a finding.
 *
 * Formula:
 *   base = severityWeight + exploitBonus + fixPenalty + envBonus
 *   score = base × log10(assetCount + 1 + 1)  [clamped to 100]
 */
export function computeRiskScore(finding: Finding, assetCount: number): number {
  let base = SEVERITY_WEIGHTS[finding.severity] ?? 10

  // Exploit factors
  if (finding.exploitKnown) base += 25
  else if (finding.exploitAvailable) base += 20
  else if (finding.exploitPoC) base += 12

  // No fix increases remediation risk
  if (!finding.fixedVersion) base += 10

  // Production exposure
  const env = (finding.environment ?? '').toLowerCase()
  if (env.includes('prod')) base += 15
  else if (env.includes('staging') || env.includes('stag')) base += 8

  // Asset exposure multiplier
  const multiplier = Math.log10(Math.max(assetCount, 1) + 1)
  const raw = base * multiplier

  return Math.min(100, Math.round(raw))
}

/**
 * Compute the overall security posture score (0–100, higher is better).
 *
 * Uses a weighted penalty model: each finding's risk contribution is summed
 * and normalised against the theoretical maximum risk.
 */
export function computeSecurityScore(findings: Finding[]): number {
  if (findings.length === 0) return 100

  let totalRisk = 0
  for (const f of findings) {
    let weight = SEVERITY_WEIGHTS[f.severity] ?? 10
    if (f.exploitKnown) weight += 25
    else if (f.exploitAvailable) weight += 20
    if (!f.fixedVersion) weight += 10
    const env = (f.environment ?? '').toLowerCase()
    if (env.includes('prod')) weight += 15
    totalRisk += weight
  }

  // Normalise: treat findings.length × max-weight (100) as absolute zero
  const maxRisk = findings.length * 100
  const score = Math.max(0, Math.round((1 - totalRisk / maxRisk) * 100))
  return score
}

/**
 * Derive the fix status for a finding.
 */
const NO_FIX_STRINGS = new Set([
  'no', 'none', 'n/a', 'na', 'false', 'unavailable', 'not available',
  'no fix', 'no fix available', 'not fixed', 'unfixed', '-', '',
])

export function getFixStatus(finding: Finding): FixStatus {
  const fv = (finding.fixedVersion ?? '').trim().toLowerCase()
  // Treat explicit "no fix" placeholders as NONE
  if (NO_FIX_STRINGS.has(fv)) {
    // Only return NONE if there's actually a value (not blank → UNKNOWN)
    return fv === '' ? 'UNKNOWN' : 'NONE'
  }
  if (finding.fixedVersion && finding.fixedVersion.trim() !== '') return 'AVAILABLE'
  // Some scanners expose fix status in a separate field
  const raw = String(finding.raw?.fixStatus ?? finding.raw?.fix_status ?? '').toLowerCase()
  if (raw === 'none' || raw === 'unavailable' || raw === 'not available' || raw === 'n/a') {
    return 'NONE'
  }
  return 'UNKNOWN'
}

/**
 * Assign a risk priority label to a finding.
 *
 * Rules (in priority order):
 *   IMMEDIATE     – Critical severity, OR (High + known/available exploit in prod)
 *   HIGH_PRIORITY – High severity, OR (any severity with known exploit)
 *   SCHEDULED_FIX – Medium severity with a fix available
 *   MONITOR       – Everything else
 */
export function getPriorityLabel(finding: Finding): RiskPriority {
  const isCritical = finding.severity === 'CRITICAL'
  const isHigh = finding.severity === 'HIGH'
  const isMedium = finding.severity === 'MEDIUM'
  const hasExploit = finding.exploitKnown || finding.exploitAvailable
  const isProd = (finding.environment ?? '').toLowerCase().includes('prod')

  if (isCritical || (isHigh && hasExploit && isProd)) return 'IMMEDIATE'
  if (isHigh || (hasExploit && (isCritical || isHigh)) || (isCritical && !hasExploit)) {
    return 'HIGH_PRIORITY'
  }
  if (isMedium && !!finding.fixedVersion) return 'SCHEDULED_FIX'
  if (isMedium || (hasExploit)) return 'HIGH_PRIORITY'
  return 'MONITOR'
}

export const PRIORITY_CONFIG: Record<
  RiskPriority,
  { label: string; emoji: string; color: string; bg: string; border: string }
> = {
  IMMEDIATE: {
    label: 'Immediate Action',
    emoji: '🔴',
    color: 'text-red-700',
    bg: 'bg-red-50',
    border: 'border-red-200',
  },
  HIGH_PRIORITY: {
    label: 'High Priority',
    emoji: '🟠',
    color: 'text-orange-700',
    bg: 'bg-orange-50',
    border: 'border-orange-200',
  },
  SCHEDULED_FIX: {
    label: 'Scheduled Fix',
    emoji: '🟡',
    color: 'text-yellow-700',
    bg: 'bg-yellow-50',
    border: 'border-yellow-200',
  },
  MONITOR: {
    label: 'Monitor',
    emoji: '🟢',
    color: 'text-green-700',
    bg: 'bg-green-50',
    border: 'border-green-200',
  },
}

export const FIX_STATUS_CONFIG: Record<
  FixStatus,
  { label: string; color: string; bg: string }
> = {
  AVAILABLE: { label: 'Fix Available', color: 'text-green-700', bg: 'bg-green-50' },
  NONE: { label: 'No Fix Available', color: 'text-red-700', bg: 'bg-red-50' },
  UNKNOWN: { label: 'Unknown', color: 'text-gray-600', bg: 'bg-gray-50' },
}

export const CONCEPT_TOOLTIPS: Record<string, string> = {
  CVE: 'CVE (Common Vulnerabilities and Exposures) — a publicly disclosed security vulnerability with a unique CVE-YYYY-NNNNN identifier.',
  CVSS: 'CVSS (Common Vulnerability Scoring System) — measures how severe a vulnerability is based on exploitability and impact. Scores range from 0 (none) to 10 (critical).',
  Exploitability: 'Exploitability — how easily an attacker can exploit a vulnerability. A high exploitability score means less skill or access is required.',
  Severity:
    'Severity — a qualitative label (Critical, High, Medium, Low) indicating overall risk. Derived from CVSS score and context.',
  'Fix Availability':
    'Fix Availability — whether a patched version or workaround exists. Findings without a fix require compensating controls until a patch is released.',
  'Risk Score':
    'Risk Score — a calculated composite score combining severity, exploit likelihood, fix availability, and environment exposure. Higher = more urgent.',
  'Security Score':
    'Security Score — a 0–100 posture metric. 100 = no risk. Score decreases with more critical, exploitable, or unpatched findings.',
  'Blast Radius':
    'Blast Radius — the number of distinct assets affected by a single CVE. A high blast radius means one unpatched vulnerability impacts many systems.',
}
