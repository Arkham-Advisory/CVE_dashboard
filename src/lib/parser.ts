import Papa from 'papaparse'
import * as XLSX from 'xlsx'
import type { Finding, ColumnMapping, Upload } from '@/types'
import type { Severity } from '@/types'

const CVE_REGEX = /CVE-\d{4}-\d+/i

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
  // Check header names first
  const candidates = ['cve', 'cve_id', 'cveid', 'cve id', 'vulnerability', 'vuln_id']
  for (const h of headers) {
    if (candidates.includes(h.toLowerCase().replace(/[^a-z_]/g, ''))) {
      return h
    }
  }
  return undefined
}

export function detectColumnsFromRows(
  headers: string[],
  rows: Record<string, unknown>[],
): ColumnMapping {
  const mapping: ColumnMapping = {}

  // Try to detect CVE column by scanning values
  for (const h of headers) {
    const sample = rows
      .slice(0, 20)
      .map((r) => String(r[h] ?? ''))
      .join(' ')
    if (CVE_REGEX.test(sample)) {
      mapping.cveId = h
      break
    }
  }

  // Fallback: check header names for CVE
  if (!mapping.cveId) {
    mapping.cveId = detectCVEColumn(headers)
  }

  // Heuristic column detection
  for (const h of headers) {
    const lower = h.toLowerCase()
    if (!mapping.severity && (lower.includes('severity') || lower.includes('criticality')))
      mapping.severity = h
    if (
      !mapping.assetName &&
      (lower.includes('asset') ||
        lower.includes('instance') ||
        lower.includes('host') ||
        lower.includes('resource'))
    )
      mapping.assetName = h
    if (!mapping.assetType && lower.includes('asset_type')) mapping.assetType = h
    if (!mapping.packageName && (lower.includes('package') || lower.includes('pkg')))
      mapping.packageName = h
    if (!mapping.installedVersion && (lower.includes('installed') || lower.includes('version')))
      mapping.installedVersion = h
    if (
      !mapping.fixedVersion &&
      (lower.includes('fixed') || lower.includes('remediat') || lower.includes('patch'))
    )
      mapping.fixedVersion = h
    if (!mapping.account && (lower.includes('account') || lower.includes('aws_account')))
      mapping.account = h
    if (!mapping.region && lower.includes('region')) mapping.region = h
    if (
      !mapping.description &&
      (lower.includes('description') || lower.includes('title') || lower.includes('summary'))
    )
      mapping.description = h
  }

  return mapping
}

function rowsToFindings(
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
        severity: mapping.severity
          ? normalizeSeverity(row[mapping.severity])
          : 'UNKNOWN',
        assetName: mapping.assetName ? String(row[mapping.assetName] ?? '') || undefined : undefined,
        assetType: mapping.assetType
          ? String(row[mapping.assetType] ?? '') || undefined
          : undefined,
        packageName: mapping.packageName
          ? String(row[mapping.packageName] ?? '') || undefined
          : undefined,
        installedVersion: mapping.installedVersion
          ? String(row[mapping.installedVersion] ?? '') || undefined
          : undefined,
        fixedVersion: mapping.fixedVersion
          ? String(row[mapping.fixedVersion] ?? '') || undefined
          : undefined,
        account: mapping.account ? String(row[mapping.account] ?? '') || undefined : undefined,
        region: mapping.region ? String(row[mapping.region] ?? '') || undefined : undefined,
        description: mapping.description
          ? String(row[mapping.description] ?? '') || undefined
          : undefined,
        sourceFile,
        raw: row,
      })
    }
  }

  return findings
}

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

export async function parseFile(file: File): Promise<{
  findings: Finding[]
  upload: Upload
  mapping: ColumnMapping
}> {
  let rows: Record<string, unknown>[]
  let headers: string[]

  const ext = file.name.split('.').pop()?.toLowerCase()
  if (ext === 'csv') {
    ;({ rows, headers } = await parseCSV(file))
  } else if (ext === 'xlsx' || ext === 'xls') {
    ;({ rows, headers } = await parseXLSX(file))
  } else {
    throw new Error(`Unsupported file format: ${ext}`)
  }

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
  }

  return { findings, upload, mapping }
}
