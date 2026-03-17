import type { NVDCVEData } from '@/types'

const NVD_BASE = 'https://services.nvd.nist.gov/rest/json/cves/2.0'
const CACHE_PREFIX = 'nvd_v2_'
const CACHE_TTL = 24 * 60 * 60 * 1000 // 24 h

// ── Rate limiter: max 4 requests per 30 seconds (NVD allows 5 w/o API key) ──
const WINDOW_MS = 30_000
const MAX_PER_WINDOW = 4
let requestTimestamps: number[] = []
const pendingQueue: Array<() => void> = []

function canRequest(): boolean {
  const now = Date.now()
  requestTimestamps = requestTimestamps.filter((t) => now - t < WINDOW_MS)
  return requestTimestamps.length < MAX_PER_WINDOW
}

function scheduleNext() {
  if (pendingQueue.length === 0) return
  if (canRequest()) {
    const next = pendingQueue.shift()
    next?.()
  } else {
    const oldest = requestTimestamps[0]
    const wait = WINDOW_MS - (Date.now() - oldest) + 100
    setTimeout(scheduleNext, wait)
  }
}

function waitForSlot(): Promise<void> {
  return new Promise((resolve) => {
    const attempt = () => {
      if (canRequest()) {
        requestTimestamps.push(Date.now())
        resolve()
        setTimeout(scheduleNext, 0)
      } else {
        pendingQueue.push(attempt)
        scheduleNext()
      }
    }
    attempt()
  })
}

// ── Cache helpers ─────────────────────────────────────────────────────────────

function cacheGet(cveId: string): NVDCVEData | null {
  try {
    const raw = localStorage.getItem(CACHE_PREFIX + cveId)
    if (!raw) return null
    const data = JSON.parse(raw) as NVDCVEData
    if (Date.now() - data.fetchedAt > CACHE_TTL) {
      localStorage.removeItem(CACHE_PREFIX + cveId)
      return null
    }
    return data
  } catch {
    return null
  }
}

function cacheSet(data: NVDCVEData) {
  try {
    localStorage.setItem(CACHE_PREFIX + data.cveId, JSON.stringify(data))
  } catch {
    // localStorage full – silently ignore
  }
}

// ── NVD response parser ───────────────────────────────────────────────────────

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function parseNVD(cveId: string, cve: any): NVDCVEData {
  const desc: string =
    cve.descriptions?.find((d: { lang: string; value: string }) => d.lang === 'en')?.value ?? ''

  const metrics = cve.metrics ?? {}
  const v31 = metrics.cvssMetricV31?.[0]
  const v30 = metrics.cvssMetricV30?.[0]
  const v2 = metrics.cvssMetricV2?.[0]
  const bestV3 = v31 ?? v30

  const references: NVDCVEData['references'] = (cve.references ?? []).map(
    (r: { url: string; source?: string; tags?: string[] }) => ({
      url: r.url,
      source: r.source,
      tags: r.tags,
    }),
  )

  const cwes: string[] = []
  for (const w of cve.weaknesses ?? []) {
    for (const d of w.description ?? []) {
      if (d.lang === 'en' && d.value && d.value !== 'NVD-CWE-Other') {
        cwes.push(d.value)
      }
    }
  }

  return {
    cveId,
    description: desc,
    cvssV3Score: bestV3?.cvssData?.baseScore,
    cvssV3Vector: bestV3?.cvssData?.vectorString,
    cvssV3BaseSeverity: bestV3?.cvssData?.baseSeverity,
    cvssV2Score: v2?.cvssData?.baseScore,
    exploitabilityScore: bestV3?.exploitabilityScore,
    impactScore: bestV3?.impactScore,
    cwes,
    references,
    publishedDate: cve.published ?? '',
    lastModifiedDate: cve.lastModified ?? '',
    fetchedAt: Date.now(),
  }
}

// ── Public API ────────────────────────────────────────────────────────────────

export async function fetchCVE(cveId: string): Promise<NVDCVEData | null> {
  const cached = cacheGet(cveId)
  if (cached) return cached

  try {
    await waitForSlot()
    const res = await fetch(`${NVD_BASE}?cveId=${encodeURIComponent(cveId)}`)
    if (!res.ok) return null
    const json = await res.json()
    const cve = json.vulnerabilities?.[0]?.cve
    if (!cve) return null
    const data = parseNVD(cveId, cve)
    cacheSet(data)
    return data
  } catch {
    return null
  }
}

/** Fetch a batch of CVE IDs, respecting rate limits. Calls onData as each result arrives. */
export async function fetchCVEBatch(
  cveIds: string[],
  onData: (id: string, data: NVDCVEData | null) => void,
  onProgress?: (done: number, total: number) => void,
) {
  let done = 0
  const total = cveIds.length
  await Promise.all(
    cveIds.map(async (id) => {
      const data = await fetchCVE(id)
      onData(id, data)
      done++
      onProgress?.(done, total)
    }),
  )
}

/** Estimated CVSS score from severity when NVD data is unavailable */
export function estimateCVSS(severity: string): number {
  switch (severity.toUpperCase()) {
    case 'CRITICAL': return 9.5
    case 'HIGH': return 8.0
    case 'MEDIUM': return 5.5
    case 'LOW': return 2.0
    default: return 0
  }
}
