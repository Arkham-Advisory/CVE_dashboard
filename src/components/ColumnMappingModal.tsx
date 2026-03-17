import { useState, useEffect } from 'react'
import { Settings, AlertCircle, Sparkles } from 'lucide-react'
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogFooter,
  DialogDescription,
} from '@/components/ui/dialog'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { ScrollArea } from '@/components/ui/scroll-area'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import type { ColumnMapping } from '@/types'

const NONE_VALUE = '__none__'

interface MappingField {
  key: keyof ColumnMapping
  label: string
  description: string
  required?: boolean
}

const MAPPING_FIELDS: MappingField[] = [
  {
    key: 'cveId',
    label: 'CVE ID',
    description: 'Column containing CVE identifiers (e.g. CVE-2023-1234)',
    required: true,
  },
  {
    key: 'severity',
    label: 'Severity',
    description: 'Risk severity level — CRITICAL, HIGH, MEDIUM, LOW',
  },
  {
    key: 'assetName',
    label: 'Asset / Resource Name',
    description: 'Name or ID of the affected resource (instance ID, hostname, etc.)',
  },
  {
    key: 'arn',
    label: 'Resource ARN',
    description:
      'AWS ARN of the vulnerable resource — scanner ARNs (Inspector, SecurityHub) are excluded automatically',
  },
  {
    key: 'assetType',
    label: 'Asset Type',
    description: 'Type of resource — EC2, Lambda, Container, S3…',
  },
  {
    key: 'packageName',
    label: 'Package Name',
    description: 'Vulnerable package or library name',
  },
  {
    key: 'installedVersion',
    label: 'Installed Version',
    description: 'Currently installed / affected version',
  },
  {
    key: 'fixedVersion',
    label: 'Fixed In Version',
    description: 'Version where the vulnerability is remediated',
  },
  {
    key: 'account',
    label: 'Account ID',
    description: 'AWS account ID or tenant identifier (12-digit or slug)',
  },
  {
    key: 'accountName',
    label: 'Account Name',
    description: 'Human-readable account label or alias (shown in place of the raw ID)',
  },
  {
    key: 'region',
    label: 'Region',
    description: 'AWS region or datacenter location',
  },
  {
    key: 'description',
    label: 'Description',
    description: 'CVE description or vulnerability title',
  },
  {
    key: 'sla',
    label: 'SLA / Due Date',
    description: 'Remediation deadline, SLA breach date, or target fix date',
  },
]

function getSampleValues(col: string, rows: Record<string, unknown>[]): string[] {
  const seen = new Set<string>()
  const samples: string[] = []
  for (const row of rows) {
    if (samples.length >= 3) break
    const v = String(row[col] ?? '').trim()
    if (v && v !== 'null' && v !== 'undefined' && !seen.has(v)) {
      seen.add(v)
      samples.push(v.length > 60 ? v.slice(0, 57) + '…' : v)
    }
  }
  return samples
}

interface Props {
  open: boolean
  fileName: string
  columns: string[]
  sampleRows: Record<string, unknown>[]
  initialMapping: ColumnMapping
  onApply: (mapping: ColumnMapping) => void
  onCancel: () => void
}

export function ColumnMappingModal({
  open,
  fileName,
  columns,
  sampleRows,
  initialMapping,
  onApply,
  onCancel,
}: Props) {
  const [mapping, setMapping] = useState<ColumnMapping>({ ...initialMapping })

  // Reset whenever initialMapping changes (new file or remap trigger)
  useEffect(() => {
    setMapping({ ...initialMapping })
  }, [initialMapping, open])

  const set = (key: keyof ColumnMapping, value: string) => {
    setMapping((m) => ({ ...m, [key]: value === NONE_VALUE ? undefined : value }))
  }

  const autoDetectedCount = MAPPING_FIELDS.filter((f) => initialMapping[f.key]).length
  const mappedCount = MAPPING_FIELDS.filter((f) => mapping[f.key]).length

  return (
    <Dialog open={open} onOpenChange={(o) => !o && onCancel()}>
      <DialogContent className="max-w-2xl max-h-[92vh] flex flex-col gap-0 p-0">
        <DialogHeader className="px-6 pt-6 pb-4 border-b">
          <DialogTitle className="flex items-center gap-2 text-base">
            <Settings className="h-4 w-4" />
            Column Mapping — {fileName}
          </DialogTitle>
          <DialogDescription className="flex items-center gap-1.5 text-xs mt-1">
            <Sparkles className="h-3.5 w-3.5 text-primary" />
            {autoDetectedCount} of {MAPPING_FIELDS.length} fields auto-detected. Review and adjust before importing.
          </DialogDescription>
        </DialogHeader>

        <ScrollArea className="flex-1 px-6 py-4">
          <div className="space-y-1.5">
            {MAPPING_FIELDS.map(({ key, label, description, required }) => {
              const selected = mapping[key]
              const samples = selected ? getSampleValues(selected, sampleRows) : []
              const isAutoDetected = !!initialMapping[key] && initialMapping[key] === selected

              return (
                <div
                  key={key}
                  className={`grid grid-cols-[1fr_210px] items-start gap-3 rounded-lg border px-3 py-2.5 transition-colors ${
                    selected
                      ? 'border-primary/40 bg-primary/[0.03]'
                      : required
                        ? 'border-destructive/40 bg-destructive/[0.03]'
                        : 'border-border'
                  }`}
                >
                  <div className="min-w-0">
                    <div className="flex items-center gap-1.5 flex-wrap">
                      <span className="text-xs font-medium">{label}</span>
                      {required && (
                        <Badge variant="destructive" className="text-[10px] h-4 px-1">
                          required
                        </Badge>
                      )}
                      {isAutoDetected && selected && (
                        <Badge variant="secondary" className="text-[10px] h-4 px-1 gap-0.5">
                          <Sparkles className="h-2.5 w-2.5" /> auto
                        </Badge>
                      )}
                    </div>
                    <p className="text-[11px] text-muted-foreground mt-0.5 leading-relaxed">
                      {description}
                    </p>
                    {samples.length > 0 && (
                      <div className="mt-1 space-y-0.5">
                        {samples.map((s, i) => (
                          <p key={i} className="text-[10px] font-mono text-muted-foreground/70 italic truncate">
                            {i === 0 ? 'e.g. ' : '     '}{s}
                          </p>
                        ))}
                      </div>
                    )}
                  </div>

                  <Select value={selected ?? NONE_VALUE} onValueChange={(v) => set(key, v)}>
                    <SelectTrigger className="h-8 text-xs mt-0.5">
                      <SelectValue placeholder="— None —" />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value={NONE_VALUE} className="text-xs text-muted-foreground">
                        — None —
                      </SelectItem>
                      {columns.map((col) => (
                        <SelectItem key={col} value={col} className="text-xs font-mono">
                          {col}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </div>
              )
            })}
          </div>
        </ScrollArea>

        {!mapping.cveId && (
          <div className="mx-6 mb-2 flex items-center gap-2 rounded-md bg-destructive/10 px-3 py-2 text-xs text-destructive">
            <AlertCircle className="h-3.5 w-3.5 shrink-0" />
            A CVE ID column is required to import findings.
          </div>
        )}

        <DialogFooter className="border-t px-6 py-4 flex items-center justify-between">
          <span className="text-xs text-muted-foreground">
            {mappedCount} field{mappedCount !== 1 ? 's' : ''} mapped
          </span>
          <div className="flex gap-2">
            <Button variant="outline" size="sm" onClick={onCancel}>
              Skip File
            </Button>
            <Button size="sm" onClick={() => onApply(mapping)} disabled={!mapping.cveId}>
              Apply & Import
            </Button>
          </div>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
