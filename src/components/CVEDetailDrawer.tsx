import { useEffect, useMemo, useState } from 'react'
import { X, ExternalLink, Shield, AlertCircle, Loader2, Zap, ShieldAlert, FlaskConical, GitBranch, Wrench } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { SeverityBadge } from '@/components/SeverityBadge'
import { PriorityBadge } from '@/components/PriorityBadge'
import { FixStatusBadge } from '@/components/FixStatusBadge'
import { InfoTooltip } from '@/components/InfoTooltip'
import { AssetTypeIcon, parseARN } from '@/components/AssetTypeIcon'
import { ScrollArea } from '@/components/ui/scroll-area'
import { Separator } from '@/components/ui/separator'
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from '@/components/ui/tooltip'
import { useAppStore } from '@/store/useAppStore'
import { useCVEDataStore } from '@/store/useCVEDataStore'
import { getFixStatus, CONCEPT_TOOLTIPS } from '@/lib/riskScore'
import type { Finding } from '@/types'

// Fix Simulation component
function FixSimulator({ findings, packages }: { findings: Finding[]; packages: string[] }) {
  const [selectedPkg, setSelectedPkg] = useState<string>('')

  const simulation = useMemo(() => {
    if (!selectedPkg) return null
    const affected = findings.filter((f) => f.packageName === selectedPkg)
    const resolved = affected.filter((f) => !!f.fixedVersion)
    const unresolved = affected.filter((f) => !f.fixedVersion)
    const versions = Array.from(new Set(affected.map((f) => f.installedVersion).filter(Boolean)))
    const fixVersions = Array.from(new Set(resolved.map((f) => f.fixedVersion).filter(Boolean)))
    const assets = Array.from(new Set(affected.map((f) => f.assetName).filter(Boolean)))
    return { affected: affected.length, resolved: resolved.length, unresolved: unresolved.length, versions, fixVersions, assets: assets.length }
  }, [findings, selectedPkg])

  return (
    <div className="rounded-lg border border-blue-200 bg-blue-50 p-3 space-y-3">
      <h3 className="text-xs font-semibold text-blue-800 uppercase tracking-wide flex items-center gap-1.5">
        <Wrench className="h-3.5 w-3.5" /> Fix Simulation
      </h3>
      <p className="text-xs text-blue-700">Select a package to simulate upgrading it and see how many findings would be resolved.</p>
      <select
        className="w-full text-xs rounded border border-blue-200 bg-white px-2 py-1.5 focus:outline-none focus:ring-2 focus:ring-blue-400"
        value={selectedPkg}
        onChange={(e) => setSelectedPkg(e.target.value)}
      >
        <option value="">— Select package to upgrade —</option>
        {packages.map((pkg) => {
          const pkgFindings = findings.filter((f) => f.packageName === pkg)
          const fixable = pkgFindings.filter((f) => !!f.fixedVersion).length
          return (
            <option key={pkg} value={pkg}>
              {pkg} ({fixable}/{pkgFindings.length} fixable)
            </option>
          )
        })}
      </select>
      {simulation && (
        <div className="rounded bg-white border border-blue-200 p-3 space-y-2 text-xs">
          <div className="font-semibold text-blue-900">Simulating upgrade of {selectedPkg}</div>
          {simulation.fixVersions.length > 0 && (
            <div className="text-muted-foreground">
              Target version: <span className="font-mono text-green-600 font-medium">{simulation.fixVersions.join(' / ')}</span>
            </div>
          )}
          {simulation.versions.length > 0 && (
            <div className="text-muted-foreground">
              Installed: <span className="font-mono">{simulation.versions.join(', ')}</span>
            </div>
          )}
          <div className="flex gap-4 pt-1">
            <div className="text-center">
              <div className="text-lg font-bold text-green-600">{simulation.resolved}</div>
              <div className="text-[10px] text-muted-foreground">Resolved</div>
            </div>
            <div className="text-center">
              <div className="text-lg font-bold text-orange-500">{simulation.unresolved}</div>
              <div className="text-[10px] text-muted-foreground">Remaining</div>
            </div>
            <div className="text-center">
              <div className="text-lg font-bold text-blue-600">{simulation.assets}</div>
              <div className="text-[10px] text-muted-foreground">Assets affected</div>
            </div>
          </div>
          {simulation.resolved === 0 && (
            <p className="text-orange-600 text-[11px]">⚠ No fix version available for this package — upgrading may not resolve findings.</p>
          )}
          {simulation.resolved === simulation.affected && (
            <p className="text-green-600 text-[11px]">✓ All {simulation.affected} findings for this package would be resolved by this upgrade.</p>
          )}
        </div>
      )}
    </div>
  )
}


function CVSSGauge({ score, label }: { score: number; label: string }) {
  const pct = Math.min(100, (score / 10) * 100)
  const color =
    score >= 9 ? '#ef4444' : score >= 7 ? '#f97316' : score >= 4 ? '#eab308' : '#3b82f6'
  return (
    <div className="space-y-1">
      <div className="flex justify-between text-xs">
        <span className="text-muted-foreground">{label}</span>
        <span className="font-bold" style={{ color }}>
          {score.toFixed(1)}
        </span>
      </div>
      <div className="h-2 rounded-full bg-secondary overflow-hidden">
        <div
          className="h-full rounded-full transition-all"
          style={{ width: `${pct}%`, backgroundColor: color }}
        />
      </div>
    </div>
  )
}

export function CVEDetailDrawer() {
  const { selectedCVE, setSelectedCVE } = useAppStore()
  const { data: nvdData, loading, fetchOne } = useCVEDataStore()

  useEffect(() => {
    if (selectedCVE) fetchOne(selectedCVE.cveId)
  }, [selectedCVE, fetchOne])

  // Aggregate exploit info across all findings
  const exploitInfo = useMemo(() => {
    if (!selectedCVE) return { known: false, available: false, poc: false }
    return {
      known: selectedCVE.findings.some((f) => f.exploitKnown),
      available: selectedCVE.findings.some((f) => f.exploitAvailable),
      poc: selectedCVE.findings.some((f) => f.exploitPoC),
    }
  }, [selectedCVE])

  // Dependency chain: which packages pull in this CVE
  const dependencyChain = useMemo(() => {
    if (!selectedCVE) return []
    const pkgs = new Set<string>()
    for (const f of selectedCVE.findings) {
      if (f.packageName) pkgs.add(f.packageName)
    }
    return Array.from(pkgs)
  }, [selectedCVE])

  if (!selectedCVE) return null

  const nvd = nvdData[selectedCVE.cveId]
  const isLoading = loading.has(selectedCVE.cveId)
  const uniqueAssets = Array.from(
    new Set(selectedCVE.findings.map((f) => f.assetName).filter(Boolean)),
  )
  const fixableCount = selectedCVE.findings.filter((f) => !!f.fixedVersion).length
  const topPriority = selectedCVE.findings
    .map((f) => f.priorityLabel)
    .filter(Boolean)
    .sort((a, b) => {
      const ord: Record<string, number> = { IMMEDIATE: 0, HIGH_PRIORITY: 1, SCHEDULED_FIX: 2, MONITOR: 3 }
      return (ord[a!] ?? 3) - (ord[b!] ?? 3)
    })[0]

  const description = nvd?.description || selectedCVE.description

  return (
    <div className="fixed inset-0 z-50 flex">
      {/* Backdrop */}
      <div className="flex-1 bg-black/40" onClick={() => setSelectedCVE(null)} />

      {/* Drawer */}
      <div className="w-full max-w-4xl bg-background border-l shadow-xl flex flex-col">
        {/* Header */}
        <div className="flex items-start justify-between p-6 border-b gap-4">
          <div className="space-y-1.5 flex-1 min-w-0">
            <div className="flex items-center gap-2 flex-wrap">
              <SeverityBadge severity={selectedCVE.severity} />
              {topPriority && <PriorityBadge priority={topPriority} />}
              {nvd?.cvssV3Score && (
                <Badge variant="outline" className="font-mono text-xs gap-1">
                  <Shield className="h-3 w-3" />
                  CVSS {nvd.cvssV3Score.toFixed(1)}
                  <InfoTooltip content={CONCEPT_TOOLTIPS['CVSS']} />
                </Badge>
              )}
              {isLoading && (
                <span className="flex items-center gap-1 text-xs text-muted-foreground">
                  <Loader2 className="h-3 w-3 animate-spin" /> Loading NVD data…
                </span>
              )}
            </div>
            <h2 className="text-lg font-semibold font-mono">{selectedCVE.cveId}</h2>
            {description && (
              <p className="text-sm text-muted-foreground leading-relaxed line-clamp-3">
                {description}
              </p>
            )}
          </div>
          <Button variant="ghost" size="icon" className="shrink-0" onClick={() => setSelectedCVE(null)}>
            <X className="h-4 w-4" />
          </Button>
        </div>

        <ScrollArea className="flex-1">
          <div className="p-6 space-y-6">
            {/* Exploit Intelligence Flags */}
            {(exploitInfo.known || exploitInfo.available || exploitInfo.poc) && (
              <div className="rounded-lg border border-orange-200 bg-orange-50 p-3 space-y-2">
                <h3 className="text-xs font-semibold text-orange-800 uppercase tracking-wide flex items-center gap-1.5">
                  <Zap className="h-3.5 w-3.5" /> Exploit Intelligence
                  <InfoTooltip content={CONCEPT_TOOLTIPS['Exploitability']} />
                </h3>
                <div className="flex flex-wrap gap-2">
                  {exploitInfo.known && (
                    <TooltipProvider>
                      <Tooltip>
                        <TooltipTrigger asChild>
                          <span className="inline-flex items-center gap-1 rounded bg-red-100 border border-red-300 text-red-700 px-2 py-1 text-xs font-semibold">
                            <Zap className="h-3.5 w-3.5" /> Known Exploited (KEV)
                          </span>
                        </TooltipTrigger>
                        <TooltipContent>This CVE is in CISA's Known Exploited Vulnerabilities catalog — actively exploited in the wild.</TooltipContent>
                      </Tooltip>
                    </TooltipProvider>
                  )}
                  {exploitInfo.available && (
                    <TooltipProvider>
                      <Tooltip>
                        <TooltipTrigger asChild>
                          <span className="inline-flex items-center gap-1 rounded bg-orange-100 border border-orange-300 text-orange-700 px-2 py-1 text-xs font-semibold">
                            <ShieldAlert className="h-3.5 w-3.5" /> Exploit Available
                          </span>
                        </TooltipTrigger>
                        <TooltipContent>A working exploit is publicly available for this vulnerability.</TooltipContent>
                      </Tooltip>
                    </TooltipProvider>
                  )}
                  {exploitInfo.poc && (
                    <TooltipProvider>
                      <Tooltip>
                        <TooltipTrigger asChild>
                          <span className="inline-flex items-center gap-1 rounded bg-yellow-100 border border-yellow-300 text-yellow-700 px-2 py-1 text-xs font-semibold">
                            <FlaskConical className="h-3.5 w-3.5" /> PoC Exists
                          </span>
                        </TooltipTrigger>
                        <TooltipContent>A proof-of-concept demonstrating the vulnerability exists.</TooltipContent>
                      </Tooltip>
                    </TooltipProvider>
                  )}
                </div>
              </div>
            )}

            {/* Summary Stats */}
            <div className="grid grid-cols-4 gap-3">
              {[
                { label: 'Findings', value: selectedCVE.findings.length },
                { label: 'Assets', value: selectedCVE.affectedAssets },
                { label: 'Packages', value: selectedCVE.packages.length },
                { label: 'Fixable', value: fixableCount, highlight: fixableCount > 0 },
              ].map(({ label, value, highlight }) => (
                <div key={label} className="rounded-lg border p-3 text-center">
                  <div className={`text-xl font-bold ${highlight ? 'text-green-600' : ''}`}>
                    {value}
                  </div>
                  <div className="text-xs text-muted-foreground mt-0.5">{label}</div>
                </div>
              ))}
            </div>

            {/* Fix Status Summary */}
            <div className="flex items-center gap-3 flex-wrap">
              <span className="text-xs text-muted-foreground font-medium">Fix Status:</span>
              {(() => {
                const statuses = selectedCVE.findings.map((f) => getFixStatus(f))
                const avail = statuses.filter((s) => s === 'AVAILABLE').length
                const none = statuses.filter((s) => s === 'NONE').length
                const unk = statuses.filter((s) => s === 'UNKNOWN').length
                return (
                  <>
                    {avail > 0 && <FixStatusBadge status="AVAILABLE" />}
                    {none > 0 && <FixStatusBadge status="NONE" />}
                    {unk > 0 && <FixStatusBadge status="UNKNOWN" />}
                    <InfoTooltip content={CONCEPT_TOOLTIPS['Fix Availability']} />
                  </>
                )
              })()}
            </div>

            {/* CVSS Scores */}
            {nvd && (nvd.cvssV3Score || nvd.cvssV2Score) && (
              <div className="rounded-lg border p-4 space-y-3">
                <h3 className="text-sm font-semibold flex items-center gap-2">
                  <Shield className="h-4 w-4" /> CVSS Scores
                </h3>
                {nvd.cvssV3Score && (
                  <CVSSGauge score={nvd.cvssV3Score} label="CVSS v3 Base Score" />
                )}
                {nvd.cvssV2Score && (
                  <CVSSGauge score={nvd.cvssV2Score} label="CVSS v2 Base Score" />
                )}
                {nvd.exploitabilityScore && (
                  <CVSSGauge score={nvd.exploitabilityScore} label="Exploitability" />
                )}
                {nvd.impactScore && (
                  <CVSSGauge score={nvd.impactScore} label="Impact" />
                )}
                {nvd.cvssV3Vector && (
                  <div className="font-mono text-[10px] text-muted-foreground break-all bg-muted/30 rounded px-2 py-1">
                    {nvd.cvssV3Vector}
                  </div>
                )}
              </div>
            )}

            {/* NVD Metadata */}
            {nvd && (
              <div className="grid grid-cols-2 gap-3 text-xs">
                {nvd.cwes.length > 0 && (
                  <div>
                    <div className="font-medium mb-1 text-muted-foreground uppercase tracking-wide text-[10px]">
                      Weakness (CWE)
                    </div>
                    <div className="flex flex-wrap gap-1">
                      {nvd.cwes.map((c) => (
                        <Badge key={c} variant="outline" className="font-mono text-[10px]">
                          {c}
                        </Badge>
                      ))}
                    </div>
                  </div>
                )}
                {nvd.publishedDate && (
                  <div>
                    <div className="font-medium mb-1 text-muted-foreground uppercase tracking-wide text-[10px]">
                      Published
                    </div>
                    <div>{new Date(nvd.publishedDate).toLocaleDateString()}</div>
                  </div>
                )}
              </div>
            )}

            {/* References */}
            {nvd && nvd.references.length > 0 && (
              <div>
                <h3 className="text-sm font-semibold mb-2 flex items-center gap-2">
                  <ExternalLink className="h-4 w-4" /> References
                </h3>
                <div className="space-y-1 max-h-40 overflow-y-auto">
                  {nvd.references.slice(0, 10).map((ref, i) => (
                    <a
                      key={i}
                      href={ref.url}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="flex items-start gap-2 text-xs text-primary hover:underline break-all"
                    >
                      <ExternalLink className="h-3 w-3 shrink-0 mt-0.5" />
                      <span className="truncate">{ref.url}</span>
                      {ref.tags?.map((t) => (
                        <Badge key={t} variant="secondary" className="text-[10px] shrink-0">
                          {t}
                        </Badge>
                      ))}
                    </a>
                  ))}
                </div>
              </div>
            )}

            {/* Dependency Chain / Affected Packages */}
            {dependencyChain.length > 0 && (
              <div>
                <h3 className="text-sm font-semibold mb-3 flex items-center gap-2">
                  <GitBranch className="h-4 w-4" /> Dependency Chain
                </h3>
                <div className="rounded-md border overflow-hidden">
                  <table className="w-full text-xs">
                    <thead className="bg-muted/50">
                      <tr>
                        <th className="text-left px-3 py-2 font-medium text-muted-foreground">Package</th>
                        <th className="text-left px-3 py-2 font-medium text-muted-foreground">Installed</th>
                        <th className="text-left px-3 py-2 font-medium text-muted-foreground">Fix Version</th>
                        <th className="text-right px-3 py-2 font-medium text-muted-foreground">Findings</th>
                        <th className="text-right px-3 py-2 font-medium text-muted-foreground">Assets</th>
                      </tr>
                    </thead>
                    <tbody>
                      {dependencyChain.map((pkg, i) => {
                        const pkgFindings = selectedCVE.findings.filter((f) => f.packageName === pkg)
                        const versions = Array.from(new Set(pkgFindings.map((f) => f.installedVersion).filter(Boolean)))
                        const fixes = Array.from(new Set(pkgFindings.map((f) => f.fixedVersion).filter(Boolean)))
                        const assetsCount = new Set(pkgFindings.map((f) => f.assetName).filter(Boolean)).size
                        const hasFix = fixes.length > 0
                        return (
                          <tr key={pkg} className={`border-t ${i % 2 ? 'bg-muted/10' : ''}`}>
                            <td className="px-3 py-2 font-mono font-semibold">{pkg}</td>
                            <td className="px-3 py-2 font-mono text-muted-foreground">
                              {versions.length > 0 ? versions.join(', ') : <span className="text-muted-foreground/40">—</span>}
                            </td>
                            <td className="px-3 py-2 font-mono">
                              {hasFix ? (
                                <span className="text-green-600 font-medium">{fixes.join(', ')}</span>
                              ) : (
                                <span className="text-orange-500 text-[11px] font-medium">No fix available</span>
                              )}
                            </td>
                            <td className="px-3 py-2 text-right">
                              <span className="inline-flex items-center justify-center rounded-full bg-primary/10 text-primary font-semibold px-2 py-0.5 min-w-[1.5rem]">
                                {pkgFindings.length}
                              </span>
                            </td>
                            <td className="px-3 py-2 text-right text-muted-foreground">{assetsCount}</td>
                          </tr>
                        )
                      })}
                    </tbody>
                  </table>
                </div>
              </div>
            )}

            <Separator />

            {/* Fix Simulation */}
            {dependencyChain.length > 0 && (
              <FixSimulator findings={selectedCVE.findings} packages={dependencyChain} />
            )}

            {/* Findings Table */}
            <div>
              <h3 className="text-sm font-semibold mb-3">Findings Detail</h3>
              <div className="rounded-md border overflow-hidden">
                <table className="w-full text-sm">
                  <thead className="bg-muted/50">
                    <tr>
                      <th className="text-left px-3 py-2 font-medium text-xs text-muted-foreground">Asset</th>
                      <th className="text-left px-3 py-2 font-medium text-xs text-muted-foreground">Type</th>
                      <th className="text-left px-3 py-2 font-medium text-xs text-muted-foreground">Package</th>
                      <th className="text-left px-3 py-2 font-medium text-xs text-muted-foreground">Installed</th>
                      <th className="text-left px-3 py-2 font-medium text-xs text-muted-foreground">Fixed</th>
                      <th className="text-left px-3 py-2 font-medium text-xs text-muted-foreground">Account</th>
                      <th className="text-left px-3 py-2 font-medium text-xs text-muted-foreground">Region</th>
                      <th className="text-left px-3 py-2 font-medium text-xs text-muted-foreground">SLA</th>
                    </tr>
                  </thead>
                  <tbody>
                    {selectedCVE.findings.map((f, i) => {
                      const arnParsed = f.arn ? parseARN(f.arn) : null
                      return (
                        <tr key={f.id} className={i % 2 === 0 ? '' : 'bg-muted/20'}>
                          <td className="px-3 py-2 max-w-[140px]">
                            <TooltipProvider>
                              <Tooltip>
                                <TooltipTrigger asChild>
                                  <div className="flex items-center gap-1 cursor-default">
                                    <AssetTypeIcon
                                      arn={f.arn}
                                      assetType={f.assetType}
                                      assetName={f.assetName}
                                    />
                                    <span className="font-mono text-xs truncate max-w-[110px]">
                                      {f.assetName ?? '—'}
                                    </span>
                                  </div>
                                </TooltipTrigger>
                                {f.arn && (
                                  <TooltipContent>
                                    <p className="font-mono text-xs break-all max-w-xs">{f.arn}</p>
                                    {arnParsed && (
                                      <p className="text-xs text-muted-foreground mt-1">
                                        {arnParsed.service} · {arnParsed.accountId} · {arnParsed.region}
                                      </p>
                                    )}
                                  </TooltipContent>
                                )}
                              </Tooltip>
                            </TooltipProvider>
                          </td>
                          <td className="px-3 py-2 text-xs text-muted-foreground">{f.assetType ?? arnParsed?.service ?? '—'}</td>
                          <td className="px-3 py-2 font-mono text-xs">{f.packageName ?? '—'}</td>
                          <td className="px-3 py-2 font-mono text-xs">{f.installedVersion ?? '—'}</td>
                          <td className="px-3 py-2 font-mono text-xs text-green-600 font-medium">
                            {f.fixedVersion ?? <span className="text-muted-foreground font-normal">—</span>}
                          </td>
                          <td className="px-3 py-2 text-xs text-muted-foreground" title={f.account}>
                            {f.accountName ?? f.account ?? '—'}
                          </td>
                          <td className="px-3 py-2 text-xs text-muted-foreground">
                            {f.region ?? arnParsed?.region ?? '—'}
                          </td>
                          <td className="px-3 py-2 text-xs">
                            {f.sla ? (
                              (() => {
                                const d = new Date(f.sla)
                                const isDate = !isNaN(d.getTime())
                                const breached = isDate && d < new Date()
                                return (
                                  <span className={breached ? 'text-destructive font-semibold' : 'text-muted-foreground'}>
                                    {isDate ? d.toLocaleDateString() : f.sla}
                                  </span>
                                )
                              })()
                            ) : (
                              <span className="text-muted-foreground">—</span>
                            )}
                          </td>
                        </tr>
                      )
                    })}
                  </tbody>
                </table>
              </div>
            </div>

            {uniqueAssets.length > 0 && (
              <div>
                <h3 className="text-sm font-semibold mb-2">
                  All Affected Assets ({uniqueAssets.length})
                </h3>
                <div className="grid grid-cols-1 gap-1">
                  {uniqueAssets.map((asset) => {
                    const finding = selectedCVE.findings.find((f) => f.assetName === asset)
                    const arnParsed = finding?.arn ? parseARN(finding.arn) : null
                    return (
                      <div
                        key={asset}
                        className="flex items-center gap-2 bg-muted/30 rounded px-2 py-1.5"
                      >
                        <AssetTypeIcon
                          arn={finding?.arn}
                          assetType={finding?.assetType}
                          assetName={asset ?? undefined}
                        />
                        <span className="text-xs font-mono truncate flex-1" title={finding?.arn ?? asset ?? undefined}>
                          {asset}
                        </span>
                        {arnParsed && (
                          <span className="text-[10px] text-muted-foreground shrink-0">
                            {arnParsed.region || 'global'}
                          </span>
                        )}
                        {finding?.accountName ? (
                          <Badge variant="outline" className="text-[10px]" title={finding.account}>
                            {finding.accountName}
                          </Badge>
                        ) : finding?.account ? (
                          <Badge variant="outline" className="text-[10px]">
                            {finding.account}
                          </Badge>
                        ) : null}
                      </div>
                    )
                  })}
                </div>
              </div>
            )}

            {/* NVD Attribution */}
            {nvd && (
              <div className="flex items-center gap-2 text-[10px] text-muted-foreground border-t pt-4">
                <AlertCircle className="h-3 w-3" />
                Data from NIST NVD · Last modified {new Date(nvd.lastModifiedDate).toLocaleDateString()}
                <a
                  href={`https://nvd.nist.gov/vuln/detail/${selectedCVE.cveId}`}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="ml-auto flex items-center gap-1 text-primary hover:underline"
                >
                  View on NVD <ExternalLink className="h-3 w-3" />
                </a>
              </div>
            )}
          </div>
        </ScrollArea>
      </div>
    </div>
  )
}
