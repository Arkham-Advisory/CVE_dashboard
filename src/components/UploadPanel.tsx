import { useCallback, useState } from 'react'
import { Upload, FileSpreadsheet, AlertCircle } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { useAppStore } from '@/store/useAppStore'
import { parseFile } from '@/lib/parser'

export function UploadPanel() {
  const [dragging, setDragging] = useState(false)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const { addFindings, uploads, clearAll } = useAppStore()

  const processFiles = useCallback(
    async (files: File[]) => {
      setLoading(true)
      setError(null)
      try {
        for (const file of files) {
          const { findings, upload } = await parseFile(file)
          addFindings(findings, upload)
        }
      } catch (e) {
        setError(e instanceof Error ? e.message : 'Failed to parse file')
      } finally {
        setLoading(false)
      }
    },
    [addFindings],
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

  return (
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
          onDragOver={(e) => {
            e.preventDefault()
            setDragging(true)
          }}
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
                <span className="text-xs text-muted-foreground">
                  {u.rowCount.toLocaleString()} rows
                </span>
              </div>
            ))}
          </div>
        )}
      </CardContent>
    </Card>
  )
}
