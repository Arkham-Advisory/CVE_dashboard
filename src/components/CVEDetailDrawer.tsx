import { X } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { SeverityBadge } from '@/components/SeverityBadge'
import { ScrollArea } from '@/components/ui/scroll-area'
import { Separator } from '@/components/ui/separator'
import { useAppStore } from '@/store/useAppStore'

export function CVEDetailDrawer() {
  const { selectedCVE, setSelectedCVE } = useAppStore()

  if (!selectedCVE) return null

  const uniqueAssets = Array.from(new Set(selectedCVE.findings.map((f) => f.assetName).filter(Boolean)))

  return (
    <div className="fixed inset-0 z-50 flex">
      {/* Backdrop */}
      <div
        className="flex-1 bg-black/40"
        onClick={() => setSelectedCVE(null)}
      />
      {/* Drawer */}
      <div className="w-full max-w-2xl bg-background border-l shadow-xl flex flex-col">
        {/* Header */}
        <div className="flex items-center justify-between p-6 border-b">
          <div className="space-y-1">
            <div className="flex items-center gap-2">
              <SeverityBadge severity={selectedCVE.severity} />
              <h2 className="text-lg font-semibold font-mono">{selectedCVE.cveId}</h2>
            </div>
            {selectedCVE.description && (
              <p className="text-sm text-muted-foreground line-clamp-2">{selectedCVE.description}</p>
            )}
          </div>
          <Button variant="ghost" size="icon" onClick={() => setSelectedCVE(null)}>
            <X className="h-4 w-4" />
          </Button>
        </div>

        <ScrollArea className="flex-1">
          <div className="p-6 space-y-6">
            {/* Summary Stats */}
            <div className="grid grid-cols-3 gap-4">
              <div className="rounded-lg border p-4 text-center">
                <div className="text-2xl font-bold">{selectedCVE.findings.length}</div>
                <div className="text-xs text-muted-foreground mt-1">Total Findings</div>
              </div>
              <div className="rounded-lg border p-4 text-center">
                <div className="text-2xl font-bold">{selectedCVE.affectedAssets}</div>
                <div className="text-xs text-muted-foreground mt-1">Affected Assets</div>
              </div>
              <div className="rounded-lg border p-4 text-center">
                <div className="text-2xl font-bold">{selectedCVE.packages.length}</div>
                <div className="text-xs text-muted-foreground mt-1">Packages</div>
              </div>
            </div>

            {/* Packages */}
            {selectedCVE.packages.length > 0 && (
              <div>
                <h3 className="text-sm font-semibold mb-2">Affected Packages</h3>
                <div className="flex flex-wrap gap-2">
                  {selectedCVE.packages.map((pkg) => (
                    <span
                      key={pkg}
                      className="rounded-md bg-secondary px-2 py-1 text-xs font-mono"
                    >
                      {pkg}
                    </span>
                  ))}
                </div>
              </div>
            )}

            <Separator />

            {/* Asset Table */}
            <div>
              <h3 className="text-sm font-semibold mb-3">Findings Detail</h3>
              <div className="rounded-md border overflow-hidden">
                <table className="w-full text-sm">
                  <thead className="bg-muted/50">
                    <tr>
                      <th className="text-left px-3 py-2 font-medium text-xs text-muted-foreground">
                        Asset
                      </th>
                      <th className="text-left px-3 py-2 font-medium text-xs text-muted-foreground">
                        Package
                      </th>
                      <th className="text-left px-3 py-2 font-medium text-xs text-muted-foreground">
                        Installed
                      </th>
                      <th className="text-left px-3 py-2 font-medium text-xs text-muted-foreground">
                        Fixed
                      </th>
                    </tr>
                  </thead>
                  <tbody>
                    {selectedCVE.findings.map((f, i) => (
                      <tr
                        key={f.id}
                        className={i % 2 === 0 ? '' : 'bg-muted/20'}
                      >
                        <td className="px-3 py-2 font-mono text-xs truncate max-w-[140px]" title={f.assetName}>
                          {f.assetName ?? '—'}
                        </td>
                        <td className="px-3 py-2 font-mono text-xs">{f.packageName ?? '—'}</td>
                        <td className="px-3 py-2 font-mono text-xs">{f.installedVersion ?? '—'}</td>
                        <td className="px-3 py-2 font-mono text-xs text-green-600">
                          {f.fixedVersion ?? '—'}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>

            {uniqueAssets.length > 0 && (
              <div>
                <h3 className="text-sm font-semibold mb-2">Affected Assets ({uniqueAssets.length})</h3>
                <div className="space-y-1">
                  {uniqueAssets.map((asset) => (
                    <div key={asset} className="text-xs font-mono bg-muted/30 rounded px-2 py-1">
                      {asset}
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        </ScrollArea>
      </div>
    </div>
  )
}
