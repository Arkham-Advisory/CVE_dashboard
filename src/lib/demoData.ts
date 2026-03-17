import type { Finding, Upload, ColumnMapping } from '@/types'
import { computeRiskScore, getPriorityLabel } from './riskScore'

// ── Demo raw rows ─────────────────────────────────────────────────────────────

const DEMO_ROWS = [
  // CRITICAL — production — exploit known — no fix
  { cveId: 'CVE-2021-44228', severity: 'CRITICAL', asset: 'api-prod-1', type: 'EC2', pkg: 'log4j-core', installed: '2.14.0', fixed: '2.15.0', account: '123456789012', accountName: 'production', region: 'us-east-1', env: 'production', exploitAvail: true, exploitKnown: true, exploitPoC: true, treatment: 'Patch', findingType: 'Package Vulnerability', desc: 'Log4Shell remote code execution via JNDI lookup' },
  { cveId: 'CVE-2021-44228', severity: 'CRITICAL', asset: 'worker-prod-2', type: 'EC2', pkg: 'log4j-core', installed: '2.14.0', fixed: '2.15.0', account: '123456789012', accountName: 'production', region: 'us-east-1', env: 'production', exploitAvail: true, exploitKnown: true, exploitPoC: true, treatment: 'Patch', findingType: 'Package Vulnerability', desc: 'Log4Shell remote code execution via JNDI lookup' },
  { cveId: 'CVE-2021-44228', severity: 'CRITICAL', asset: 'container-frontend', type: 'Container', pkg: 'log4j-core', installed: '2.13.0', fixed: '2.15.0', account: '234567890123', accountName: 'staging', region: 'eu-west-1', env: 'staging', exploitAvail: true, exploitKnown: true, exploitPoC: true, treatment: 'Patch', findingType: 'Package Vulnerability', desc: 'Log4Shell remote code execution via JNDI lookup' },
  // CRITICAL — production — exploit available — fix available
  { cveId: 'CVE-2022-22965', severity: 'CRITICAL', asset: 'api-prod-1', type: 'EC2', pkg: 'spring-webmvc', installed: '5.3.17', fixed: '5.3.18', account: '123456789012', accountName: 'production', region: 'us-east-1', env: 'production', exploitAvail: true, exploitKnown: false, exploitPoC: true, treatment: 'Patch', findingType: 'Package Vulnerability', desc: 'Spring4Shell — RCE via data binding' },
  { cveId: 'CVE-2022-22965', severity: 'CRITICAL', asset: 'api-prod-2', type: 'EC2', pkg: 'spring-webmvc', installed: '5.3.17', fixed: '5.3.18', account: '123456789012', accountName: 'production', region: 'us-west-2', env: 'production', exploitAvail: true, exploitKnown: false, exploitPoC: true, treatment: 'Patch', findingType: 'Package Vulnerability', desc: 'Spring4Shell — RCE via data binding' },
  // CRITICAL — no fix available
  { cveId: 'CVE-2023-38408', severity: 'CRITICAL', asset: 'bastion-host', type: 'EC2', pkg: 'openssh', installed: '9.1p1', fixed: '', account: '123456789012', accountName: 'production', region: 'us-east-1', env: 'production', exploitAvail: false, exploitKnown: false, exploitPoC: false, treatment: 'Mitigate', findingType: 'OS Package', desc: 'OpenSSH pre-auth RCE in ssh-agent' },
  { cveId: 'CVE-2023-38408', severity: 'CRITICAL', asset: 'jump-server-eu', type: 'EC2', pkg: 'openssh', installed: '9.1p1', fixed: '', account: '234567890123', accountName: 'staging', region: 'eu-west-1', env: 'staging', exploitAvail: false, exploitKnown: false, exploitPoC: false, treatment: 'Mitigate', findingType: 'OS Package', desc: 'OpenSSH pre-auth RCE in ssh-agent' },
  // HIGH — exploit available
  { cveId: 'CVE-2023-44487', severity: 'HIGH', asset: 'api-prod-1', type: 'EC2', pkg: 'nghttp2', installed: '1.50.0', fixed: '1.57.0', account: '123456789012', accountName: 'production', region: 'us-east-1', env: 'production', exploitAvail: true, exploitKnown: false, exploitPoC: false, treatment: 'Patch', findingType: 'Package Vulnerability', desc: 'HTTP/2 Rapid Reset attack (DoS)' },
  { cveId: 'CVE-2023-44487', severity: 'HIGH', asset: 'nginx-lb-prod', type: 'EC2', pkg: 'nghttp2', installed: '1.50.0', fixed: '1.57.0', account: '123456789012', accountName: 'production', region: 'us-east-1', env: 'production', exploitAvail: true, exploitKnown: false, exploitPoC: false, treatment: 'Patch', findingType: 'Package Vulnerability', desc: 'HTTP/2 Rapid Reset attack (DoS)' },
  { cveId: 'CVE-2023-44487', severity: 'HIGH', asset: 'container-frontend', type: 'Container', pkg: 'nghttp2', installed: '1.48.0', fixed: '1.57.0', account: '345678901234', accountName: 'development', region: 'us-east-1', env: 'development', exploitAvail: true, exploitKnown: false, exploitPoC: false, treatment: 'Patch', findingType: 'Package Vulnerability', desc: 'HTTP/2 Rapid Reset attack (DoS)' },
  // HIGH — no fix
  { cveId: 'CVE-2024-3094', severity: 'HIGH', asset: 'build-server-1', type: 'EC2', pkg: 'xz-utils', installed: '5.6.0', fixed: '5.6.1', account: '123456789012', accountName: 'production', region: 'us-east-1', env: 'production', exploitAvail: false, exploitKnown: false, exploitPoC: true, treatment: 'Patch', findingType: 'Supply Chain', desc: 'XZ Utils backdoor (supply chain attack)' },
  { cveId: 'CVE-2024-3094', severity: 'HIGH', asset: 'build-server-2', type: 'EC2', pkg: 'xz-utils', installed: '5.6.0', fixed: '5.6.1', account: '234567890123', accountName: 'staging', region: 'eu-west-1', env: 'staging', exploitAvail: false, exploitKnown: false, exploitPoC: true, treatment: 'Patch', findingType: 'Supply Chain', desc: 'XZ Utils backdoor (supply chain attack)' },
  // HIGH — production
  { cveId: 'CVE-2021-3618', severity: 'HIGH', asset: 'nginx-lb-prod', type: 'EC2', pkg: 'nginx', installed: '1.20.0', fixed: '1.20.2', account: '123456789012', accountName: 'production', region: 'us-east-1', env: 'production', exploitAvail: false, exploitKnown: false, exploitPoC: false, treatment: 'Patch', findingType: 'Package Vulnerability', desc: 'ALPACA attack on TLS' },
  { cveId: 'CVE-2021-3618', severity: 'HIGH', asset: 'nginx-lb-staging', type: 'EC2', pkg: 'nginx', installed: '1.20.0', fixed: '1.20.2', account: '234567890123', accountName: 'staging', region: 'eu-west-1', env: 'staging', exploitAvail: false, exploitKnown: false, exploitPoC: false, treatment: 'Patch', findingType: 'Package Vulnerability', desc: 'ALPACA attack on TLS' },
  { cveId: 'CVE-2021-3618', severity: 'HIGH', asset: 'api-prod-2', type: 'EC2', pkg: 'nginx', installed: '1.20.0', fixed: '1.20.2', account: '123456789012', accountName: 'production', region: 'us-west-2', env: 'production', exploitAvail: false, exploitKnown: false, exploitPoC: false, treatment: 'Patch', findingType: 'Package Vulnerability', desc: 'ALPACA attack on TLS' },
  // MEDIUM — fix available
  { cveId: 'CVE-2022-37434', severity: 'MEDIUM', asset: 'api-prod-1', type: 'EC2', pkg: 'zlib', installed: '1.2.11', fixed: '1.2.12', account: '123456789012', accountName: 'production', region: 'us-east-1', env: 'production', exploitAvail: false, exploitKnown: false, exploitPoC: false, treatment: 'Patch', findingType: 'Package Vulnerability', desc: 'zlib heap-based buffer over-read' },
  { cveId: 'CVE-2022-37434', severity: 'MEDIUM', asset: 'worker-prod-2', type: 'EC2', pkg: 'zlib', installed: '1.2.11', fixed: '1.2.12', account: '123456789012', accountName: 'production', region: 'us-east-1', env: 'production', exploitAvail: false, exploitKnown: false, exploitPoC: false, treatment: 'Patch', findingType: 'Package Vulnerability', desc: 'zlib heap-based buffer over-read' },
  { cveId: 'CVE-2022-37434', severity: 'MEDIUM', asset: 'data-pipeline-dev', type: 'Lambda', pkg: 'zlib', installed: '1.2.11', fixed: '1.2.12', account: '345678901234', accountName: 'development', region: 'us-east-1', env: 'development', exploitAvail: false, exploitKnown: false, exploitPoC: false, treatment: 'Accept', findingType: 'Package Vulnerability', desc: 'zlib heap-based buffer over-read' },
  // MEDIUM — no fix
  { cveId: 'CVE-2023-2650', severity: 'MEDIUM', asset: 'container-frontend', type: 'Container', pkg: 'openssl', installed: '3.0.7', fixed: '', account: '234567890123', accountName: 'staging', region: 'eu-west-1', env: 'staging', exploitAvail: false, exploitKnown: false, exploitPoC: false, treatment: 'Monitor', findingType: 'OS Package', desc: 'OpenSSL excessive time in OBJ_obj2txt()' },
  { cveId: 'CVE-2023-2650', severity: 'MEDIUM', asset: 'api-prod-1', type: 'EC2', pkg: 'openssl', installed: '3.0.7', fixed: '', account: '123456789012', accountName: 'production', region: 'us-east-1', env: 'production', exploitAvail: false, exploitKnown: false, exploitPoC: false, treatment: 'Monitor', findingType: 'OS Package', desc: 'OpenSSL excessive time in OBJ_obj2txt()' },
  // MEDIUM — various packages
  { cveId: 'CVE-2022-40674', severity: 'MEDIUM', asset: 'worker-prod-2', type: 'EC2', pkg: 'expat', installed: '2.4.7', fixed: '2.4.9', account: '123456789012', accountName: 'production', region: 'us-east-1', env: 'production', exploitAvail: false, exploitKnown: false, exploitPoC: false, treatment: 'Patch', findingType: 'Package Vulnerability', desc: 'libexpat use-after-free' },
  { cveId: 'CVE-2022-40674', severity: 'MEDIUM', asset: 'nginx-lb-staging', type: 'EC2', pkg: 'expat', installed: '2.4.7', fixed: '2.4.9', account: '234567890123', accountName: 'staging', region: 'eu-west-1', env: 'staging', exploitAvail: false, exploitKnown: false, exploitPoC: false, treatment: 'Scheduled', findingType: 'Package Vulnerability', desc: 'libexpat use-after-free' },
  // MEDIUM — Python
  { cveId: 'CVE-2023-40217', severity: 'MEDIUM', asset: 'data-pipeline-dev', type: 'Lambda', pkg: 'python3', installed: '3.11.4', fixed: '3.11.5', account: '345678901234', accountName: 'development', region: 'us-east-1', env: 'development', exploitAvail: false, exploitKnown: false, exploitPoC: false, treatment: 'Patch', findingType: 'Package Vulnerability', desc: 'Python TLS handshake bypass' },
  { cveId: 'CVE-2023-40217', severity: 'MEDIUM', asset: 'ml-service-staging', type: 'EC2', pkg: 'python3', installed: '3.11.4', fixed: '3.11.5', account: '234567890123', accountName: 'staging', region: 'eu-west-1', env: 'staging', exploitAvail: false, exploitKnown: false, exploitPoC: false, treatment: 'Patch', findingType: 'Package Vulnerability', desc: 'Python TLS handshake bypass' },
  // LOW
  { cveId: 'CVE-2022-1328', severity: 'LOW', asset: 'build-server-1', type: 'EC2', pkg: 'mutt', installed: '2.0.5', fixed: '2.2.6', account: '123456789012', accountName: 'production', region: 'us-east-1', env: 'production', exploitAvail: false, exploitKnown: false, exploitPoC: false, treatment: 'Accept', findingType: 'Package Vulnerability', desc: 'mutt buffer overflow in IMAP' },
  { cveId: 'CVE-2022-1328', severity: 'LOW', asset: 'build-server-2', type: 'EC2', pkg: 'mutt', installed: '2.0.5', fixed: '2.2.6', account: '234567890123', accountName: 'staging', region: 'eu-west-1', env: 'staging', exploitAvail: false, exploitKnown: false, exploitPoC: false, treatment: 'Accept', findingType: 'Package Vulnerability', desc: 'mutt buffer overflow in IMAP' },
  { cveId: 'CVE-2023-1370', severity: 'LOW', asset: 'data-pipeline-dev', type: 'Lambda', pkg: 'json-smart', installed: '2.4.8', fixed: '2.4.9', account: '345678901234', accountName: 'development', region: 'us-east-1', env: 'development', exploitAvail: false, exploitKnown: false, exploitPoC: false, treatment: 'Patch', findingType: 'Package Vulnerability', desc: 'StackOverflow in json-smart parser' },
  { cveId: 'CVE-2023-1370', severity: 'LOW', asset: 'ml-service-staging', type: 'EC2', pkg: 'json-smart', installed: '2.4.8', fixed: '2.4.9', account: '234567890123', accountName: 'staging', region: 'eu-west-1', env: 'staging', exploitAvail: false, exploitKnown: false, exploitPoC: false, treatment: 'Accept', findingType: 'Package Vulnerability', desc: 'StackOverflow in json-smart parser' },
  // HIGH — curl
  { cveId: 'CVE-2023-38545', severity: 'HIGH', asset: 'api-prod-1', type: 'EC2', pkg: 'curl', installed: '7.88.1', fixed: '8.4.0', account: '123456789012', accountName: 'production', region: 'us-east-1', env: 'production', exploitAvail: true, exploitKnown: false, exploitPoC: true, treatment: 'Patch', findingType: 'Package Vulnerability', desc: 'curl SOCKS5 heap buffer overflow' },
  { cveId: 'CVE-2023-38545', severity: 'HIGH', asset: 'worker-prod-2', type: 'EC2', pkg: 'curl', installed: '7.88.1', fixed: '8.4.0', account: '123456789012', accountName: 'production', region: 'us-east-1', env: 'production', exploitAvail: true, exploitKnown: false, exploitPoC: true, treatment: 'Patch', findingType: 'Package Vulnerability', desc: 'curl SOCKS5 heap buffer overflow' },
  { cveId: 'CVE-2023-38545', severity: 'HIGH', asset: 'container-frontend', type: 'Container', pkg: 'curl', installed: '7.88.1', fixed: '8.4.0', account: '345678901234', accountName: 'development', region: 'us-east-1', env: 'development', exploitAvail: true, exploitKnown: false, exploitPoC: true, treatment: 'Patch', findingType: 'Package Vulnerability', desc: 'curl SOCKS5 heap buffer overflow' },
  { cveId: 'CVE-2023-38545', severity: 'HIGH', asset: 'nginx-lb-prod', type: 'EC2', pkg: 'curl', installed: '7.88.1', fixed: '8.4.0', account: '123456789012', accountName: 'production', region: 'us-east-1', env: 'production', exploitAvail: true, exploitKnown: false, exploitPoC: true, treatment: 'Patch', findingType: 'Package Vulnerability', desc: 'curl SOCKS5 heap buffer overflow' },
  // CRITICAL — openssl
  { cveId: 'CVE-2022-0778', severity: 'HIGH', asset: 'api-prod-1', type: 'EC2', pkg: 'openssl', installed: '1.1.1l', fixed: '1.1.1n', account: '123456789012', accountName: 'production', region: 'us-east-1', env: 'production', exploitAvail: false, exploitKnown: false, exploitPoC: false, treatment: 'Patch', findingType: 'OS Package', desc: 'OpenSSL infinite loop in BN_mod_sqrt()' },
  { cveId: 'CVE-2022-0778', severity: 'HIGH', asset: 'nginx-lb-prod', type: 'EC2', pkg: 'openssl', installed: '1.1.1l', fixed: '1.1.1n', account: '123456789012', accountName: 'production', region: 'us-east-1', env: 'production', exploitAvail: false, exploitKnown: false, exploitPoC: false, treatment: 'Patch', findingType: 'OS Package', desc: 'OpenSSL infinite loop in BN_mod_sqrt()' },
  { cveId: 'CVE-2022-0778', severity: 'HIGH', asset: 'bastion-host', type: 'EC2', pkg: 'openssl', installed: '1.1.1l', fixed: '1.1.1n', account: '123456789012', accountName: 'production', region: 'us-east-1', env: 'production', exploitAvail: false, exploitKnown: false, exploitPoC: false, treatment: 'Patch', findingType: 'OS Package', desc: 'OpenSSL infinite loop in BN_mod_sqrt()' },
  // MEDIUM — requests python
  { cveId: 'CVE-2023-32681', severity: 'MEDIUM', asset: 'data-pipeline-dev', type: 'Lambda', pkg: 'python-requests', installed: '2.28.2', fixed: '2.31.0', account: '345678901234', accountName: 'development', region: 'us-east-1', env: 'development', exploitAvail: false, exploitKnown: false, exploitPoC: false, treatment: 'Patch', findingType: 'Package Vulnerability', desc: 'requests proxy-authorization header leak' },
  { cveId: 'CVE-2023-32681', severity: 'MEDIUM', asset: 'ml-service-staging', type: 'EC2', pkg: 'python-requests', installed: '2.28.2', fixed: '2.31.0', account: '234567890123', accountName: 'staging', region: 'eu-west-1', env: 'staging', exploitAvail: false, exploitKnown: false, exploitPoC: false, treatment: 'Patch', findingType: 'Package Vulnerability', desc: 'requests proxy-authorization header leak' },
  // LOW — misc
  { cveId: 'CVE-2023-29659', severity: 'LOW', asset: 'container-frontend', type: 'Container', pkg: 'libheif', installed: '1.14.2', fixed: '1.15.2', account: '234567890123', accountName: 'staging', region: 'eu-west-1', env: 'staging', exploitAvail: false, exploitKnown: false, exploitPoC: false, treatment: 'Accept', findingType: 'Package Vulnerability', desc: 'libheif NULL pointer dereference' },
  { cveId: 'CVE-2023-29659', severity: 'LOW', asset: 'data-pipeline-dev', type: 'Lambda', pkg: 'libheif', installed: '1.14.2', fixed: '1.15.2', account: '345678901234', accountName: 'development', region: 'us-east-1', env: 'development', exploitAvail: false, exploitKnown: false, exploitPoC: false, treatment: 'Accept', findingType: 'Package Vulnerability', desc: 'libheif NULL pointer dereference' },
  // HIGH — container escape
  { cveId: 'CVE-2022-0847', severity: 'HIGH', asset: 'worker-prod-2', type: 'EC2', pkg: 'linux-kernel', installed: '5.14', fixed: '5.16.11', account: '123456789012', accountName: 'production', region: 'us-east-1', env: 'production', exploitAvail: true, exploitKnown: true, exploitPoC: true, treatment: 'Patch', findingType: 'Kernel Vulnerability', desc: 'Dirty Pipe — Linux kernel privilege escalation' },
  { cveId: 'CVE-2022-0847', severity: 'HIGH', asset: 'api-prod-2', type: 'EC2', pkg: 'linux-kernel', installed: '5.14', fixed: '5.16.11', account: '123456789012', accountName: 'production', region: 'us-west-2', env: 'production', exploitAvail: true, exploitKnown: true, exploitPoC: true, treatment: 'Patch', findingType: 'Kernel Vulnerability', desc: 'Dirty Pipe — Linux kernel privilege escalation' },
  { cveId: 'CVE-2022-0847', severity: 'HIGH', asset: 'build-server-1', type: 'EC2', pkg: 'linux-kernel', installed: '5.14', fixed: '5.16.11', account: '123456789012', accountName: 'production', region: 'us-east-1', env: 'production', exploitAvail: true, exploitKnown: true, exploitPoC: true, treatment: 'Patch', findingType: 'Kernel Vulnerability', desc: 'Dirty Pipe — Linux kernel privilege escalation' },
  // UNKNOWN severity (no fix label)
  { cveId: 'CVE-2020-25649', severity: 'MEDIUM', asset: 'ml-service-staging', type: 'EC2', pkg: 'jackson-databind', installed: '2.11.0', fixed: '2.12.0', account: '234567890123', accountName: 'staging', region: 'eu-west-1', env: 'staging', exploitAvail: false, exploitKnown: false, exploitPoC: false, treatment: 'Patch', findingType: 'Package Vulnerability', desc: 'Jackson-databind XML external entity injection' },
  { cveId: 'CVE-2021-25329', severity: 'HIGH', asset: 'api-prod-1', type: 'EC2', pkg: 'tomcat', installed: '9.0.43', fixed: '9.0.44', account: '123456789012', accountName: 'production', region: 'us-east-1', env: 'production', exploitAvail: false, exploitKnown: false, exploitPoC: false, treatment: 'Patch', findingType: 'Package Vulnerability', desc: 'Tomcat partial PUT incomplete cleanup' },
]

const DEMO_FILE_NAME = 'demo-dataset.csv'

export const DEMO_MAPPING: ColumnMapping = {
  cveId: 'cveId',
  severity: 'severity',
  assetName: 'asset',
  assetType: 'type',
  packageName: 'pkg',
  installedVersion: 'installed',
  fixedVersion: 'fixed',
  account: 'account',
  accountName: 'accountName',
  region: 'region',
  description: 'desc',
  environment: 'env',
  exploitAvailable: 'exploitAvail',
  exploitKnown: 'exploitKnown',
  exploitPoC: 'exploitPoC',
  treatment: 'treatment',
  findingType: 'findingType',
}

function parseBoolean(val: unknown): boolean {
  if (typeof val === 'boolean') return val
  if (typeof val === 'string') return val.toLowerCase() === 'true' || val === '1'
  return Boolean(val)
}

export function buildDemoFindings(): Finding[] {
  const findings: Finding[] = []

  // First pass: build findings without riskScore
  for (let i = 0; i < DEMO_ROWS.length; i++) {
    const row = DEMO_ROWS[i] as Record<string, unknown>
    const raw = row
    findings.push({
      id: `demo-${i}`,
      cveId: String(row.cveId),
      severity: String(row.severity) as Finding['severity'],
      assetName: String(row.asset),
      assetType: String(row.type),
      packageName: String(row.pkg),
      installedVersion: row.installed ? String(row.installed) : undefined,
      fixedVersion: row.fixed ? String(row.fixed) : undefined,
      account: String(row.account),
      accountName: String(row.accountName),
      region: String(row.region),
      description: String(row.desc),
      sourceFile: DEMO_FILE_NAME,
      environment: String(row.env),
      exploitAvailable: parseBoolean(row.exploitAvail),
      exploitKnown: parseBoolean(row.exploitKnown),
      exploitPoC: parseBoolean(row.exploitPoC),
      treatment: String(row.treatment),
      findingType: String(row.findingType),
      raw,
    })
  }

  // Compute asset counts per CVE
  const assetCountByCVE = new Map<string, number>()
  for (const f of findings) {
    const assets = new Set(findings.filter((x) => x.cveId === f.cveId).map((x) => x.assetName))
    assetCountByCVE.set(f.cveId, assets.size)
  }

  // Second pass: add risk score and priority label
  for (const f of findings) {
    const assetCount = assetCountByCVE.get(f.cveId) ?? 1
    f.riskScore = computeRiskScore(f, assetCount)
    f.priorityLabel = getPriorityLabel(f)
  }

  return findings
}

export function buildDemoUpload(): Upload {
  return {
    id: `demo-${Date.now()}`,
    fileName: DEMO_FILE_NAME,
    fileSize: 0,
    rowCount: DEMO_ROWS.length,
    uploadedAt: new Date(),
    columns: Object.keys(DEMO_ROWS[0]),
    mapping: DEMO_MAPPING,
    rawRows: DEMO_ROWS as Record<string, unknown>[],
  }
}
