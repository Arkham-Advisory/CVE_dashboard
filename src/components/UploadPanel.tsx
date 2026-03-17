import { useCallback, useState } from 'react'
import { Upload, FileSpreadsheet, AlertCircle, Settings } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { useAppStore } from '@/store/useAppStore'
import { parseFileRaw, detectColumnsFromRows, rowsToFindings } from '@/lib/parser'
import { ColumnMappingModal } from '@/components/ColumnMappingModal'
import type { ColumnMapping, Upload as UploadType } from '@/types'

interface PendingFile {
  fileName: string
  fileSize: number
  rows: Record<string, unknown>[]
  headers: string[]
  detectedMapping: ColumnMapping
}

export function UploadPanel() {
  const [dragging, setDragging] = useState(false)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [pendingFiles, setPendingFiles] = useState<PendingFile[]>([])
  const [remapTarget, setRemapTarget] = useState<UploadType | null>(null)
  const { addFindings, uploads, clearAll, remapUpload } = useAppStore()

  // --- Parse files into pending queue (no findings committed yet) ---
  const processFiles = useCallback(
    async (files: File[]) => {
      setLoading(true)
      setError(null)
      try {
        const pending: PendingFile[] = []
        for (const file of files) {
          const { rows, headers } = await parseFileRaw(file)
          const detectedMapping = detectColumnsFromRows(headers, rows)
          pending.push({ fileName: file.name, fileSize: file.size, rows, headers, detectedMapping })
        }
        setPendingFiles((prev) => [...prev, ...pending])
      } catch (e) {
        setError(e instanceof Error ? e.message : 'Failed to parse file')
      } finally {
        setLoading(false)
      }
    },
    [],
  )

  const handleDrop = useCallback(
    (e: React.DragEvent) => {
      e.preventDefault()
      setDragging(false)
      const files = Array.from(e.dataTransfer.files).filter(
        (f) => f.name.endsWith('.csv') || f.name.endsWith('.xlsx') || f.name.endsWith('.xls'),
      )
      if (files.length > 0) processFiles(files)
    },
    [processFiles],
  )

  const handleFileChange = useCallback(
    (e: React.ChangeEvent<HTMLInputElement>) => {
      const files = Array.from(e.target.files ?? [])
      if (files.length > 0) processFiles(files)
      e.target.value = ''
    },
    [processFiles],
  )

  // --- Column mapping modal: apply & import ---
  const handleApplyNewMapping = useCallback(
    (adjustedMapping: ColumnMapping) => {
      const pending = pendingFiles[0]
      if (!pending) return

      const findings = rowsToFindings(pending.rows, adjustedMapping, pending.fileName)
      const upload: UploadType = {
        id: `${pending.fileName}-${Date.now()}`,
        fileName: pending.fileName,
        fileSize: pending.fileSize,
        rowCount: pending.rows.length,
        uploadedAt: new Date(),
        columns: pending.headers,
        mapping: adjustedMapping,
        rawRows: pending.rows,
      }
      addFindings(findings, upload)
      setPendingFiles((prev) => prev.slice(1)) // advance queue
    },
    [pendingFiles, addFindings],
  )

  const handleSkipNewFile = useCallback(() => {
    setPendingFiles((prev) => prev.slice(1))
  }, [])

  // --- Column mapping modal: remap existing upload ---
  const handleApplyRemap = useCallback(
    (newMapping: ColumnMapping) => {
      if (!remapTarget) return
      remapUpload(remapTarget.id, newMapping)
      setRemapTarget(null)
    },
    [remapTarget, remapUpload],
  )

  const activePending = pendingFiles[0]

  return (
    <>
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-base">
            <Upload className="h-4 w-4" />
            Upload Vulnerability Reports
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          {/* Drop Zone */}
          <div
            onDragOver={(e) => { e.preventDefault(); setDragging(true) }}
            onDragLeave={() => setDragging(false)}
            onDrop={handleDrop}
            className={`flex flex-col items-center justify-center gap-3 rounded-lg border-2 border-dashed p-10 transition-colors ${
              dragging
                ? 'border-primary bg-primary/5'
                : 'border-muted-foreground/25 hover:border-primary/50'
            }`}
          >
            <FileSpreadsheet className="h-10 w-10 text-muted-foreground" />
            <div className="text-center">
              <p className="text-sm font-medium">Drop CSV or XLSX files here</p>
              <p className="text-xs text-muted-foreground">or click to browse</p>
            </div>
            <label>
              <input
                type="file"
                multiple
                accept=".csv,.xlsx,.xls"
                className="sr-only"
                onChange={handleFileChange}
              />
              <Button variant="outline" size="sm" asChild>
                <span>{loading ? 'Processing...' : 'Select Files'}</span>
              </Button>
            </label>
          </div>

          {error && (
            <div className="flex items-center gap-2 rounded-md bg-destructive/10 p-3 text-sm text-destructive">
              <AlertCircle className="h-4 w-4 shrink-0" />
              {error}
            </div>
          )}

          {/* Uploaded Files List */}
          {uploads.length > 0 && (
            <div className="space-y-2">
              <div className="flex items-center justify-between">
                <p className="text-xs font-medium text-muted-foreground uppercase tracking-wide">
                  Loaded Files
                </p>
                <Button
                  variant="ghost"
                  size="sm"
                  className="h-7 text-xs text-muted-foreground"
                  onClick={clearAll}
                >
                  Clear All
                </Button>
              </div>
              {uploads.map((u) => (
                <div
                  key={u.id}
                  className="flex items-center justify-between rounded-md border px-3 py-2 text-sm"
                >
                  <div className="flex items-center gap-2">
                    <FileSpreadsheet className="h-4 w-4 text-muted-foreground" />
                    <span className="font-medium">{u.fileName}</span>
                  </div>
                  <div className="flex items-center gap-2">
                    <span className="text-xs text-muted-foreground">
                      {u.rowCount.toLocaleString()} rows
                    </span>
                    <Button
                      variant="ghost"
                      size="icon"
                      className="h-6 w-6"
                      title="Remap columns"
                      onClick={() => setRemapTarget(u)}
                    >
                      <Settings className="h-3.5 w-3.5 text-muted-foreground" />
                    </Button>
                  </div>
                </div>
              ))}
            </div>
          )}
        </CardContent>
      </Card>

      {/* Column mapping modal — new file queue */}
      {activePending && (
        <ColumnMappingModal
          open={true}
          fileName={activePending.fileName}
          columns={activePending.headers}
          sampleRows={activePending.rows}
          initialMapping={activePending.detectedMapping}
          onApply={handleApplyNewMapping}
          onCancel={handleSkipNewFile}
        />
      )}

      {/* Column mapping modal — re-map existing upload */}
      {remapTarget && (
        <ColumnMappingModal
          open={true}
          fileName={remapTarget.fileName}
          columns={remapTarget.columns}
          sampleRows={remapTarget.rawRows}
          initialMapping={remapTarget.mapping}
          onApply={handleApplyRemap}
          onCancel={() => setRemapTarget(null)}
        />
      )}
    </>
  )
}
