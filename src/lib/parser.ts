import Papa from 'papaparse'
import * as XLSX from 'xlsx'
import type { Finding, ColumnMapping, Upload } from '@/types'
import type { Severity } from '@/types'

const CVE_REGEX = /CVE-\d{4}-\d+/i

// ── ARN classification ────────────────────────────────────────────────────────

/** AWS services that are *scanning / detection tools* — their ARNs identify
 *  the finding source, NOT the vulnerable resource itself. */
const SCANNER_SERVICES = new Set([
  'inspector', 'inspector2', 'securityhub', 'guardduty', 'config',
  'macie', 'accessanalyzer', 'detective', 'trustedadvisor',
  'health', 'computeoptimizer', 'wellarchitected', 'ce',
])

/** AWS services whose ARNs are actual cloud resources we care about. */
const RESOURCE_SERVICES = new Set([
  'ec2', 'lambda', 's3', 'rds', 'eks', 'ecs', 'ecr', 'elasticloadbalancing',
  'elasticbeanstalk', 'cloudfront', 'apigateway', 'dynamodb', 'sqs', 'sns',
  'elasticache', 'redshift', 'athena', 'glue', 'kms', 'secretsmanager',
  'ssm', 'codecommit', 'codebuild', 'codepipeline', 'cloudtrail', 'wafv2',
  'route53', 'acm', 'iam', 'sts', 'apprunner', 'batch', 'emr',
])

const ARN_PATTERN = /^arn:aws[\w-]*:/

/** Score an ARN column by resource-likeness vs scanner-likeness.
 *  Returns -Infinity when no ARN values found. */
function scoreARNColumn(col: string, rows: Record<string, unknown>[]): number {
  let resourceScore = 0
  let scannerScore = 0
  let arnCount = 0

  for (const row of rows.slice(0, 30)) {
    const val = String(row[col] ?? '').trim()
    if (ARN_PATTERN.test(val)) {
      arnCount++
      const service = val.split(':')[2]?.toLowerCase()
      if (service && RESOURCE_SERVICES.has(service)) resourceScore++
      else if (service && SCANNER_SERVICES.has(service)) scannerScore++
    }
  }

  if (arnCount === 0) return -Infinity
  // Penalise scanner-only ARN columns heavily; arnCount is a tiebreaker
  return (resourceScore - scannerScore * 2) * 100 + arnCount
}

// ── Helpers ───────────────────────────────────────────────────────────────────

export function normalizeSeverity(raw: unknown): Severity {
  if (typeof raw !== 'string') return 'UNKNOWN'
  const s = raw.toUpperCase().trim()
  if (s === 'CRITICAL') return 'CRITICAL'
  if (s === 'HIGH') return 'HIGH'
  if (s === 'MEDIUM') return 'MEDIUM'
  if (s === 'LOW') return 'LOW'
  if (s === 'NONE') return 'NONE'
  return 'UNKNOWN'
}

export function detectCVEColumn(headers: string[]): string | undefined {
  const candidates = ['cve', 'cve_id', 'cveid', 'cve id', 'vulnerability', 'vuln_id']
  for (const h of headers) {
    if (candidates.includes(h.toLowerCase().replace(/[^a-z_]/g, ''))) return h
  }
  return undefined
}

// ── Column auto-detection ─────────────────────────────────────────────────────

export function detectColumnsFromRows(
  headers: string[],
  rows: Record<string, unknown>[],
): ColumnMapping {
  const mapping: ColumnMapping = {}

  // CVE: scan values first, then fall back to header names
  for (const h of headers) {
    const sample = rows.slice(0, 20).map((r) => String(r[h] ?? '')).join(' ')
    if (CVE_REGEX.test(sample)) { mapping.cveId = h; break }
  }
  if (!mapping.cveId) mapping.cveId = detectCVEColumn(headers)

  // --- Heuristic column detection (one pass) ---
  for (const h of headers) {
    const lower = h.toLowerCase().replace(/\s+/g, '_')

    if (!mapping.severity && (lower.includes('severity') || lower.includes('criticality')))
      mapping.severity = h

    if (
      !mapping.assetName &&
      (lower.includes('resource_name') || lower.includes('resource_id') ||
       lower.includes('asset_name') || lower.includes('instance_id') ||
       lower.includes('host_name') || lower === 'hostname')
    ) mapping.assetName = h

    if (!mapping.assetType && (lower === 'asset_type' || lower === 'resource_type'))
      mapping.assetType = h

    if (!mapping.packageName && (lower.includes('package') || lower.includes('pkg')))
      mapping.packageName = h

    if (!mapping.installedVersion &&
        (lower.includes('installed') || lower === 'version' || lower === 'current_version'))
      mapping.installedVersion = h

    if (!mapping.fixedVersion &&
        (lower.includes('fixed') || lower.includes('remediat') || lower.includes('patch_version')))
      mapping.fixedVersion = h

    // Account: prefer explicit ID columns over name columns for the ID field
    if (!mapping.account &&
        (lower === 'account_id' || lower === 'aws_account_id' || lower === 'accountid' ||
         lower.includes('account_id') || lower === 'tenant_id'))
      mapping.account = h

    if (!mapping.account &&
        (lower.includes('account') || lower.includes('aws_account')))
      mapping.account = h

    // Account Name / label
    if (!mapping.accountName &&
        (lower === 'account_name' || lower === 'accountname' || lower === 'account_alias' ||
         lower.includes('account_name') || lower === 'account_label'))
      mapping.accountName = h

    if (!mapping.region && lower.includes('region'))
      mapping.region = h

    if (!mapping.description &&
        (lower.includes('description') || lower === 'title' || lower === 'summary' ||
         lower.includes('vuln_title')))
      mapping.description = h

    // SLA / due date
    if (!mapping.sla &&
        (lower === 'sla' || lower.includes('sla_due') || lower.includes('sla_breach') ||
         lower.includes('due_date') || lower.includes('breach_date') ||
         lower.includes('remediation_date') || lower.includes('target_date') ||
         lower.includes('compliance_date') || lower === 'deadline' ||
         lower.includes('remediation_deadline')))
      mapping.sla = h

    // Explicit ARN header names (get a score bonus)
    if (!mapping.arn &&
        (lower === 'arn' || lower === 'resource_arn' || lower === 'asset_arn' ||
         lower === 'resource_arn' || lower.includes('resource arn')))
      mapping.arn = h
  }

  // --- Smart ARN selection: pick the most resource-like ARN column ---
  const arnCandidates: Array<{ col: string; score: number }> = []
  for (const h of headers) {
    const score = scoreARNColumn(h, rows)
    if (score === -Infinity) continue
    const lower = h.toLowerCase().replace(/\s+/g, '_')
    const headerBonus =
      (lower === 'arn' || lower.includes('resource_arn') || lower.includes('asset_arn')) ? 500 : 0
    arnCandidates.push({ col: h, score: score + headerBonus })
  }
  if (arnCandidates.length > 0) {
    arnCandidates.sort((a, b) => b.score - a.score)
    mapping.arn = arnCandidates[0].col
  }

  return mapping
}

// ── Row → Findings ────────────────────────────────────────────────────────────

export function rowsToFindings(
  rows: Record<string, unknown>[],
  mapping: ColumnMapping,
  sourceFile: string,
): Finding[] {
  const findings: Finding[] = []

  for (const row of rows) {
    const rawCveField = mapping.cveId ? String(row[mapping.cveId] ?? '') : ''
    const cveMatches = rawCveField.match(/CVE-\d{4}-\d+/gi) ?? []
    if (cveMatches.length === 0) continue

    for (const cveId of cveMatches) {
      findings.push({
        id: `${sourceFile}-${cveId}-${findings.length}`,
        cveId: cveId.toUpperCase(),
        severity: mapping.severity ? normalizeSeverity(row[mapping.severity]) : 'UNKNOWN',
        assetName: mapping.assetName ? String(row[mapping.assetName] ?? '') || undefined : undefined,
        assetType: mapping.assetType ? String(row[mapping.assetType] ?? '') || undefined : undefined,
        arn: mapping.arn ? String(row[mapping.arn] ?? '') || undefined : undefined,
        packageName: mapping.packageName ? String(row[mapping.packageName] ?? '') || undefined : undefined,
        installedVersion: mapping.installedVersion ? String(row[mapping.installedVersion] ?? '') || undefined : undefined,
        fixedVersion: mapping.fixedVersion ? String(row[mapping.fixedVersion] ?? '') || undefined : undefined,
        account: mapping.account ? String(row[mapping.account] ?? '') || undefined : undefined,
        accountName: mapping.accountName ? String(row[mapping.accountName] ?? '') || undefined : undefined,
        region: mapping.region ? String(row[mapping.region] ?? '') || undefined : undefined,
        description: mapping.description ? String(row[mapping.description] ?? '') || undefined : undefined,
        sla: mapping.sla ? String(row[mapping.sla] ?? '') || undefined : undefined,
        sourceFile,
        raw: row,
      })
    }
  }

  return findings
}

// ── Format parsers ────────────────────────────────────────────────────────────

export async function parseCSV(
  file: File,
): Promise<{ rows: Record<string, unknown>[]; headers: string[] }> {
  return new Promise((resolve, reject) => {
    Papa.parse<Record<string, unknown>>(file, {
      header: true,
      skipEmptyLines: true,
      complete: (results) => {
        const headers = results.meta.fields ?? []
        resolve({ rows: results.data, headers })
      },
      error: (err) => reject(err),
    })
  })
}

export async function parseXLSX(
  file: File,
): Promise<{ rows: Record<string, unknown>[]; headers: string[] }> {
  const buffer = await file.arrayBuffer()
  const workbook = XLSX.read(buffer, { type: 'array' })
  const sheetName = workbook.SheetNames[0]
  const sheet = workbook.Sheets[sheetName]
  const rows = XLSX.utils.sheet_to_json<Record<string, unknown>>(sheet, { defval: '' })
  const headers = rows.length > 0 ? Object.keys(rows[0]) : []
  return { rows, headers }
}

export async function parseFileRaw(
  file: File,
): Promise<{ rows: Record<string, unknown>[]; headers: string[] }> {
  const ext = file.name.split('.').pop()?.toLowerCase()
  if (ext === 'csv') return parseCSV(file)
  if (ext === 'xlsx' || ext === 'xls') return parseXLSX(file)
  throw new Error(`Unsupported file format: ${ext}`)
}

export async function parseFile(file: File): Promise<{
  findings: Finding[]
  upload: Upload
  mapping: ColumnMapping
}> {
  const { rows, headers } = await parseFileRaw(file)
  const mapping = detectColumnsFromRows(headers, rows)
  const findings = rowsToFindings(rows, mapping, file.name)

  const upload: Upload = {
    id: `${file.name}-${Date.now()}`,
    fileName: file.name,
    fileSize: file.size,
    rowCount: rows.length,
    uploadedAt: new Date(),
    columns: headers,
    mapping,
    rawRows: rows,
  }

  return { findings, upload, mapping }
}
