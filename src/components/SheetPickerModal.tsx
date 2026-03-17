import { useState } from 'react'
import {
  FileSpreadsheet,
  Table2,
  CheckCircle2,
  ChevronRight,
  AlertCircle,
} from 'lucide-react'
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
  DialogFooter,
} from '@/components/ui/dialog'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import type { XLSXSheetPreview } from '@/lib/parser'

const CVE_REGEX = /CVE-\d{4}-\d+/i
const MAX_PREVIEW_COLS = 7

// Highlight CVE IDs in table cells
function CellValue({ value }: { value: unknown }) {
  const str = String(value ?? '').trim()
  if (!str || str === 'undefined') {
    return <span className="text-muted-foreground/30">—</span>
  }
  if (CVE_REGEX.test(str)) {
    return (
      <span className="font-mono text-green-700 font-semibold text-[11px] bg-green-50 rounded px-0.5">
        {str}
      </span>
    )
  }
  return <span className="truncate max-w-[160px] inline-block">{str}</span>
}

interface Props {
  open: boolean
  fileName: string
  sheets: XLSXSheetPreview[]
  onSelect: (sheetName: string) => void
  onCancel: () => void
}

export function SheetPickerModal({ open, fileName, sheets, onSelect, onCancel }: Props) {
  const [selected, setSelected] = useState<string>(() => {
    // Auto-select the first sheet that contains CVE data in its preview
    const cveSheet = sheets.find((s) =>
      s.preview.some((row) => Object.values(row).some((v) => CVE_REGEX.test(String(v)))),
    )
    // Fall back to the sheet with the most rows, then the first sheet
    const mostRows = [...sheets].sort((a, b) => b.rowCount - a.rowCount)[0]
    return (cveSheet ?? mostRows ?? sheets[0])?.name ?? ''
  })

  const sheet = sheets.find((s) => s.name === selected) ?? sheets[0]
  const visibleHeaders = sheet?.headers.slice(0, MAX_PREVIEW_COLS) ?? []
  const hiddenCols = Math.max(0, (sheet?.headers.length ?? 0) - MAX_PREVIEW_COLS)
  const hasCVEInPreview = sheet?.preview.some((row) =>
    Object.values(row).some((v) => CVE_REGEX.test(String(v))),
  )
  const isEmpty = !sheet || sheet.headers.length === 0

  return (
    <Dialog open={open} onOpenChange={(o) => !o && onCancel()}>
      <DialogContent className="max-w-5xl h-[82vh] flex flex-col gap-0 p-0 overflow-hidden">
        {/* Header */}
        <DialogHeader className="px-6 pt-5 pb-4 border-b shrink-0">
          <DialogTitle className="flex items-center gap-2 text-base">
            <FileSpreadsheet className="h-4 w-4 text-green-600" />
            Select Worksheet
          </DialogTitle>
          <DialogDescription className="text-xs mt-0.5">
            <span className="font-medium text-foreground">{fileName}</span>
            {' '}contains{' '}
            <span className="font-medium text-foreground">
              {sheets.length} sheet{sheets.length !== 1 ? 's' : ''}
            </span>
            . Select the one containing your vulnerability findings.
          </DialogDescription>
        </DialogHeader>

        {/* Body: sheet list + preview */}
        <div className="flex flex-1 min-h-0 overflow-hidden">
          {/* ── Sheet list (left sidebar) ─────────── */}
          <div className="w-56 shrink-0 border-r bg-muted/20 overflow-y-auto py-1">
            {sheets.map((s) => {
              const isSel = s.name === selected
              const hasCVE = s.preview.some((row) =>
                Object.values(row).some((v) => CVE_REGEX.test(String(v))),
              )
              return (
                <button
                  key={s.name}
                  onClick={() => setSelected(s.name)}
                  className={`w-full text-left px-3 py-3 flex items-start gap-2.5 border-l-2 transition-colors hover:bg-muted/40 ${
                    isSel ? 'border-primary bg-primary/5' : 'border-transparent'
                  }`}
                >
                  <Table2
                    className={`h-4 w-4 mt-0.5 shrink-0 ${
                      isSel ? 'text-primary' : 'text-muted-foreground'
                    }`}
                  />
                  <div className="flex-1 min-w-0 space-y-0.5">
                    <div
                      className={`text-sm font-medium truncate ${isSel ? 'text-primary' : ''}`}
                      title={s.name}
                    >
                      {s.name}
                    </div>
                    <div className="text-[11px] text-muted-foreground">
                      {s.rowCount.toLocaleString()} rows
                      {s.headers.length > 0 && ` · ${s.headers.length} cols`}
                    </div>
                    {hasCVE && (
                      <span className="inline-flex items-center gap-0.5 text-[10px] font-medium text-green-700 bg-green-50 border border-green-200 rounded px-1.5 py-0.5">
                        ✓ CVE data
                      </span>
                    )}
                    {s.rowCount === 0 && !hasCVE && (
                      <span className="text-[10px] text-muted-foreground italic">Empty</span>
                    )}
                  </div>
                  {isSel && (
                    <CheckCircle2 className="h-3.5 w-3.5 text-primary shrink-0 mt-0.5" />
                  )}
                </button>
              )
            })}
          </div>

          {/* ── Preview (right panel) ─────────────── */}
          <div className="flex-1 min-w-0 overflow-auto p-5">
            {isEmpty ? (
              <div className="flex flex-col items-center justify-center h-full gap-3 text-muted-foreground">
                <AlertCircle className="h-8 w-8" />
                <p className="text-sm">This sheet is empty — no data to preview.</p>
              </div>
            ) : (
              <div className="flex flex-col h-full gap-3">
                {/* Row / column count + CVE badge */}
                <div className="flex items-center gap-3 shrink-0">
                  <p className="text-xs text-muted-foreground flex-1">
                    Showing first{' '}
                    <span className="font-medium text-foreground">{sheet.preview.length}</span>
                    {' '}of{' '}
                    <span className="font-medium text-foreground">
                      {sheet.rowCount.toLocaleString()}
                    </span>{' '}
                    rows
                    {hiddenCols > 0 && (
                      <span>
                        {' '}· +{hiddenCols} column{hiddenCols !== 1 ? 's' : ''} not shown
                      </span>
                    )}
                  </p>
                  {hasCVEInPreview ? (
                    <Badge
                      variant="outline"
                      className="text-[10px] text-green-700 border-green-300 bg-green-50 shrink-0"
                    >
                      ✓ CVE identifiers detected
                    </Badge>
                  ) : (
                    <Badge
                      variant="outline"
                      className="text-[10px] text-orange-600 border-orange-300 bg-orange-50 shrink-0"
                    >
                      ⚠ No CVE IDs in preview rows
                    </Badge>
                  )}
                </div>

                {/* Preview table */}
                <div className="rounded-md border overflow-auto flex-1">
                  <table className="text-xs whitespace-nowrap">
                    <thead className="bg-muted/60 sticky top-0">
                      <tr>
                        <th className="px-2 py-2.5 text-muted-foreground/60 font-medium text-right text-[11px] w-8 border-r border-muted">
                          #
                        </th>
                        {visibleHeaders.map((h) => (
                          <th
                            key={h}
                            className="px-3 py-2.5 text-left font-medium text-foreground/70 max-w-[150px]"
                          >
                            <span className="truncate block max-w-[140px]" title={h}>
                              {h}
                            </span>
                          </th>
                        ))}
                        {hiddenCols > 0 && (
                          <th className="px-3 py-2.5 text-muted-foreground/40 font-medium text-left">
                            +{hiddenCols} more…
                          </th>
                        )}
                      </tr>
                    </thead>
                    <tbody>
                      {sheet.preview.length === 0 ? (
                        <tr>
                          <td
                            colSpan={visibleHeaders.length + 1 + (hiddenCols > 0 ? 1 : 0)}
                            className="px-4 py-6 text-center text-muted-foreground"
                          >
                            No data rows in preview range.
                          </td>
                        </tr>
                      ) : (
                        sheet.preview.map((row, i) => (
                          <tr key={i} className={`border-t ${i % 2 ? 'bg-muted/10' : ''}`}>
                            <td className="px-2 py-2 text-muted-foreground/40 text-right tabular-nums border-r border-muted">
                              {i + 1}
                            </td>
                            {visibleHeaders.map((h) => (
                              <td key={h} className="px-3 py-2">
                                <CellValue value={row[h]} />
                              </td>
                            ))}
                            {hiddenCols > 0 && (
                              <td className="px-3 py-2 text-muted-foreground/30">…</td>
                            )}
                          </tr>
                        ))
                      )}
                    </tbody>
                  </table>
                </div>
              </div>
            )}
          </div>
        </div>

        {/* Footer */}
        <DialogFooter className="px-6 py-4 border-t bg-muted/20 shrink-0 flex items-center gap-2">
          <Button variant="ghost" onClick={onCancel}>
            Cancel
          </Button>
          <Button
            onClick={() => onSelect(selected)}
            disabled={isEmpty}
            className="gap-1.5"
          >
            Use &ldquo;{selected}&rdquo;
            <ChevronRight className="h-4 w-4" />
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
