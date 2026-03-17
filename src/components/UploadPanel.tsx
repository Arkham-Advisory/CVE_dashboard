import { useCallback, useState, useRef } from 'react'
import { Upload, FileSpreadsheet, Settings, CheckCircle2, XCircle, Loader2, Trash2 } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { useAppStore } from '@/store/useAppStore'
import {
  parseFileRawWithProgress,
  detectColumnsFromRows,
  rowsToFindingsAsync,
  getXLSXSheetsPreview,
  type XLSXSheetPreview,
} from '@/lib/parser'
import { ColumnMappingModal } from '@/components/ColumnMappingModal'
import { SheetPickerModal } from '@/components/SheetPickerModal'
import type { ColumnMapping, Upload as UploadType } from '@/types'

// ── Per-file tracking ─────────────────────────────────────────────────────────

type FileStatus = 'reading' | 'processing' | 'ready' | 'error'

interface FileState {
  key: string
  fileName: string
  fileSize: number
  status: FileStatus
  progress: number   // 0-100
  phase: string
  error?: string
  // Populated once parsing completes:
  rows?: Record<string, unknown>[]
  headers?: string[]
  detectedMapping?: ColumnMapping
}

interface SheetPickerState {
  file: File
  sheets: XLSXSheetPreview[]
}

// ── Helpers ───────────────────────────────────────────────────────────────────

function formatBytes(bytes: number) {
  if (bytes < 1024) return `${bytes} B`
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`
}

function StatusIcon({ status }: { status: FileStatus }) {
  if (status === 'ready') return <CheckCircle2 className="h-3.5 w-3.5 text-green-500 shrink-0" />
  if (status === 'error') return <XCircle className="h-3.5 w-3.5 text-destructive shrink-0" />
  return <Loader2 className="h-3.5 w-3.5 text-primary animate-spin shrink-0" />
}

// ── Component ─────────────────────────────────────────────────────────────────

export function UploadPanel() {
  const [dragging, setDragging] = useState(false)
  const [processingFiles, setProcessingFiles] = useState<FileState[]>([])
  const [pendingQueue, setPendingQueue] = useState<FileState[]>([])  // ready → awaiting mapping
  const [remapTarget, setRemapTarget] = useState<UploadType | null>(null)
  const [sheetPicker, setSheetPicker] = useState<SheetPickerState | null>(null)
  const { addFindings, uploads, clearAll, remapUpload, removeUpload } = useAppStore()
  const processingRef = useRef(new Set<string>()) // prevent double-processing

  // Update a single file's state by key
  const updateFile = useCallback((key: string, patch: Partial<FileState>) => {
    setProcessingFiles((prev) =>
      prev.map((f) => (f.key === key ? { ...f, ...patch } : f)),
    )
  }, [])

  // Process a single File object asynchronously (non-blocking)
  const processOneFile = useCallback(
    async (file: File, sheetName?: string) => {
      const key = `${file.name}-${Date.now()}-${Math.random()}`
      if (processingRef.current.has(key)) return
      processingRef.current.add(key)

      const initial: FileState = {
        key,
        fileName: file.name,
        fileSize: file.size,
        status: 'reading',
        progress: 0,
        phase: 'Starting…',
      }
      setProcessingFiles((prev) => [...prev, initial])

      try {
        // Phase 1: read + detect columns (0-50%)
        const { rows, headers } = await parseFileRawWithProgress(file, (pct, phase) => {
          updateFile(key, { progress: pct, phase, status: 'reading' })
        }, sheetName)

        updateFile(key, { progress: 50, phase: 'Detecting columns…', status: 'reading' })
        const detectedMapping = detectColumnsFromRows(headers, rows)

        // Phase 2: convert rows to findings (50-100%)
        updateFile(key, { progress: 52, phase: 'Processing rows…', status: 'processing' })
        // We don't commit the findings yet — just pre-process so the modal can apply mapping
        // Run rowsToFindingsAsync for progress reporting; we'll redo with user's mapping later
        await rowsToFindingsAsync(rows, detectedMapping, file.name, (pct, phase) => {
          updateFile(key, { progress: pct, phase, status: 'processing' })
        })

        updateFile(key, { progress: 100, phase: 'Ready', status: 'ready', rows, headers, detectedMapping })

        // Enqueue for column mapping confirmation
        setProcessingFiles((prev) => prev.filter((f) => f.key !== key))
        setPendingQueue((prev) => [
          ...prev,
          { key, fileName: file.name, fileSize: file.size, status: 'ready', progress: 100, phase: 'Ready', rows, headers, detectedMapping },
        ])
      } catch (e) {
        updateFile(key, {
          status: 'error',
          progress: 0,
          phase: 'Failed',
          error: e instanceof Error ? e.message : 'Parse error',
        })
      } finally {
        processingRef.current.delete(key)
      }
    },
    [updateFile],
  )

  // For Excel files: read sheet metadata and show picker if multiple sheets exist
  const startSheetPicker = useCallback(
    async (file: File) => {
      const key = `${file.name}-sheets-${Date.now()}`
      const initial: FileState = {
        key,
        fileName: file.name,
        fileSize: file.size,
        status: 'reading',
        progress: 0,
        phase: 'Scanning sheets…',
      }
      setProcessingFiles((prev) => [...prev, initial])
      try {
        const sheets = await getXLSXSheetsPreview(file)
        setProcessingFiles((prev) => prev.filter((f) => f.key !== key))
        if (sheets.length <= 1) {
          // Single sheet — no picker needed, proceed directly
          processOneFile(file, sheets[0]?.name)
        } else {
          setSheetPicker({ file, sheets })
        }
      } catch (e) {
        updateFile(key, {
          status: 'error',
          phase: 'Failed to read workbook',
          error: e instanceof Error ? e.message : 'Could not read Excel file',
          progress: 0,
        })
      }
    },
    [processOneFile, updateFile],
  )

  const handleFiles = useCallback(
    (files: File[]) => {
      const valid = files.filter(
        (f) => f.name.endsWith('.csv') || f.name.endsWith('.xlsx') || f.name.endsWith('.xls'),
      )
      valid.forEach((f) => {
        const isExcel = f.name.endsWith('.xlsx') || f.name.endsWith('.xls')
        if (isExcel) {
          startSheetPicker(f)
        } else {
          processOneFile(f)
        }
      })
    },
    [processOneFile, startSheetPicker],
  )

  const handleDrop = useCallback(
    (e: React.DragEvent) => {
      e.preventDefault()
      setDragging(false)
      handleFiles(Array.from(e.dataTransfer.files))
    },
    [handleFiles],
  )

  const handleFileChange = useCallback(
    (e: React.ChangeEvent<HTMLInputElement>) => {
      handleFiles(Array.from(e.target.files ?? []))
      e.target.value = ''
    },
    [handleFiles],
  )

  // --- Column mapping modal: apply & import ---
  const handleApplyNewMapping = useCallback(
    async (adjustedMapping: ColumnMapping) => {
      const pending = pendingQueue[0]
      if (!pending || !pending.rows || !pending.headers) return

      const findings = await rowsToFindingsAsync(pending.rows, adjustedMapping, pending.fileName, () => {})
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
      setPendingQueue((prev) => prev.slice(1))
    },
    [pendingQueue, addFindings],
  )

  const handleSkipNewFile = useCallback(() => {
    setPendingQueue((prev) => prev.slice(1))
  }, [])

  const handleApplyRemap = useCallback(
    (newMapping: ColumnMapping) => {
      if (!remapTarget) return
      remapUpload(remapTarget.id, newMapping)
      setRemapTarget(null)
    },
    [remapTarget, remapUpload],
  )

  const handleSheetSelected = useCallback(
    (selectedSheet: string) => {
      if (!sheetPicker) return
      const { file } = sheetPicker
      setSheetPicker(null)
      processOneFile(file, selectedSheet)
    },
    [sheetPicker, processOneFile],
  )

  const handleSheetCancel = useCallback(() => setSheetPicker(null), [])

  const dismissError = (key: string) =>
    setProcessingFiles((prev) => prev.filter((f) => f.key !== key))

  const activePending = pendingQueue[0]
  const hasActivity = processingFiles.length > 0 || pendingQueue.length > 0

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
                <span>Select Files</span>
              </Button>
            </label>
          </div>

          {/* Per-file progress / error rows */}
          {(processingFiles.length > 0 || (pendingQueue.length > 0 && !activePending)) && (
            <div className="space-y-2">
              {processingFiles.map((f) => (
                <div key={f.key} className="rounded-md border px-3 py-2 space-y-1.5">
                  <div className="flex items-center gap-2">
                    <StatusIcon status={f.status} />
                    <span className="text-sm font-medium truncate flex-1">{f.fileName}</span>
                    <span className="text-xs text-muted-foreground shrink-0">
                      {formatBytes(f.fileSize)}
                    </span>
                    {f.status === 'error' && (
                      <button
                        className="text-muted-foreground hover:text-foreground"
                        onClick={() => dismissError(f.key)}
                      >
                        <XCircle className="h-3.5 w-3.5" />
                      </button>
                    )}
                  </div>
                  {f.status !== 'error' ? (
                    <div className="space-y-1">
                      {/* Progress bar */}
                      <div className="h-1.5 rounded-full bg-secondary overflow-hidden">
                        <div
                          className="h-full rounded-full bg-primary transition-all duration-300"
                          style={{ width: `${f.progress}%` }}
                        />
                      </div>
                      <p className="text-[10px] text-muted-foreground">{f.phase}</p>
                    </div>
                  ) : (
                    <p className="text-xs text-destructive">{f.error}</p>
                  )}
                </div>
              ))}
            </div>
          )}

          {/* Awaiting mapping confirmation indicator */}
          {pendingQueue.length > 1 && (
            <p className="text-xs text-muted-foreground">
              {pendingQueue.length} file{pendingQueue.length > 1 ? 's' : ''} ready — review mapping one by one
            </p>
          )}

          {/* Uploaded Files List */}
          {uploads.length > 0 && (
            <div className="space-y-2">
              <div className="flex items-center justify-between">
                <p className="text-xs font-medium text-muted-foreground uppercase tracking-wide">
                  Loaded Files
                </p>
                {!hasActivity && (
                  <Button
                    variant="ghost"
                    size="sm"
                    className="h-7 text-xs text-muted-foreground"
                    onClick={clearAll}
                  >
                    Clear All
                  </Button>
                )}
              </div>
              {uploads.map((u) => (
                <div
                  key={u.id}
                  className="flex items-center justify-between rounded-md border px-3 py-2 text-sm"
                >
                  <div className="flex items-center gap-2 min-w-0">
                    <FileSpreadsheet className="h-4 w-4 text-muted-foreground shrink-0" />
                    <span className="font-medium truncate">{u.fileName}</span>
                  </div>
                  <div className="flex items-center gap-1 shrink-0">
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
                    <Button
                      variant="ghost"
                      size="icon"
                      className="h-6 w-6 hover:text-destructive"
                      title="Remove file"
                      onClick={() => removeUpload(u.id)}
                    >
                      <Trash2 className="h-3.5 w-3.5 text-muted-foreground" />
                    </Button>
                  </div>
                </div>
              ))}
            </div>
          )}
        </CardContent>
      </Card>

      {/* Sheet picker modal — multi-sheet Excel workbooks */}
      {sheetPicker && (
        <SheetPickerModal
          open={true}
          fileName={sheetPicker.file.name}
          sheets={sheetPicker.sheets}
          onSelect={handleSheetSelected}
          onCancel={handleSheetCancel}
        />
      )}

      {/* Column mapping modal — new file queue */}
      {activePending && (
        <ColumnMappingModal
          open={true}
          fileName={activePending.fileName}
          columns={activePending.headers ?? []}
          sampleRows={activePending.rows ?? []}
          initialMapping={activePending.detectedMapping ?? {}}
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
