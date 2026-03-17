import { useState, useMemo } from 'react'
import { useSearchParams } from 'react-router-dom'
import {
  useReactTable,
  getCoreRowModel,
  getFilteredRowModel,
  getSortedRowModel,
  getPaginationRowModel,
  createColumnHelper,
  flexRender,
  type SortingState,
  type ColumnDef,
} from '@tanstack/react-table'
import {
  ArrowUpDown,
  ChevronLeft,
  ChevronRight,
  Search,
  SlidersHorizontal,
  CheckSquare2,
  X,
  Zap,
  ShieldAlert,
  FlaskConical,
  Link2,
  Check,
  Flag,
  Globe,
} from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Badge } from '@/components/ui/badge'
import { SeverityBadge } from '@/components/SeverityBadge'
import { PriorityBadge } from '@/components/PriorityBadge'
import { FixStatusBadge } from '@/components/FixStatusBadge'
import { AssetTypeIcon, parseARN } from '@/components/AssetTypeIcon'
import { Checkbox } from '@/components/ui/checkbox'
import { Separator } from '@/components/ui/separator'
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from '@/components/ui/tooltip'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { useAppStore } from '@/store/useAppStore'
import { getFixStatus } from '@/lib/riskScore'
import type { Finding, Severity, FixStatus, RiskPriority } from '@/types'
import { SEVERITY_ORDER } from '@/types'

function parseList(val: string | null): string[] {
  return val ? val.split(',').filter(Boolean) : []
}

const SEVERITIES: Severity[] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'NONE', 'UNKNOWN']

// Multi-select popover for severities
function SeverityFilter({
  selected,
  onChange,
}: {
  selected: Severity[]
  onChange: (v: Severity[]) => void
}) {
  const [open, setOpen] = useState(false)
  const toggle = (s: Severity) =>
    onChange(selected.includes(s) ? selected.filter((x) => x !== s) : [...selected, s])

  return (
    <div className="relative">
      <Button
        variant="outline"
        size="sm"
        className="gap-1.5 h-8 text-xs"
        onClick={() => setOpen((o) => !o)}
      >
        <SlidersHorizontal className="h-3.5 w-3.5" />
        Severity
        {selected.length > 0 && (
          <Badge variant="secondary" className="h-4 px-1 text-[10px]">
            {selected.length}
          </Badge>
        )}
      </Button>
      {open && (
        <div className="absolute top-full mt-1 left-0 z-30 bg-popover border rounded-md shadow-md p-2 space-y-1 min-w-[140px]">
          <button
            className="w-full text-left px-2 py-1.5 text-xs hover:bg-muted rounded"
            onClick={() => onChange([])}
          >
            <CheckSquare2 className="inline h-3.5 w-3.5 mr-1.5" />
            Clear all
          </button>
          <Separator />
          {SEVERITIES.map((s) => (
            <label
              key={s}
              className="flex items-center gap-2 rounded px-2 py-1.5 hover:bg-muted cursor-pointer"
            >
              <Checkbox
                checked={selected.includes(s)}
                onCheckedChange={() => toggle(s)}
                className="h-3.5 w-3.5"
              />
              <SeverityBadge severity={s} />
            </label>
          ))}
          <button
            className="w-full text-right px-2 py-1.5 text-xs text-primary hover:underline"
            onClick={() => setOpen(false)}
          >
            Done
          </button>
        </div>
      )}
    </div>
  )
}

// Exploit intelligence badges shown under CVE ID
function ExploitFlags({ finding }: { finding: Finding }) {
  if (!finding.exploitKnown && !finding.exploitAvailable && !finding.exploitPoC) return null
  return (
    <TooltipProvider delayDuration={300}>
      <div className="flex items-center gap-1 mt-0.5">
        {finding.exploitKnown && (
          <Tooltip>
            <TooltipTrigger asChild>
              <span className="inline-flex items-center gap-0.5 rounded bg-red-100 border border-red-300 text-red-700 px-1 py-0.5 text-[10px] font-semibold cursor-default">
                <Zap className="h-2.5 w-2.5" /> KEV
              </span>
            </TooltipTrigger>
            <TooltipContent>Known Exploited Vulnerability (actively exploited in the wild)</TooltipContent>
          </Tooltip>
        )}
        {finding.exploitAvailable && (
          <Tooltip>
            <TooltipTrigger asChild>
              <span className="inline-flex items-center gap-0.5 rounded bg-orange-100 border border-orange-300 text-orange-700 px-1 py-0.5 text-[10px] font-semibold cursor-default">
                <ShieldAlert className="h-2.5 w-2.5" /> Exploit
              </span>
            </TooltipTrigger>
            <TooltipContent>A working exploit is publicly available</TooltipContent>
          </Tooltip>
        )}
        {finding.exploitPoC && (
          <Tooltip>
            <TooltipTrigger asChild>
              <span className="inline-flex items-center gap-0.5 rounded bg-yellow-100 border border-yellow-300 text-yellow-700 px-1 py-0.5 text-[10px] font-semibold cursor-default">
                <FlaskConical className="h-2.5 w-2.5" /> PoC
              </span>
            </TooltipTrigger>
            <TooltipContent>Proof-of-concept exploit code exists</TooltipContent>
          </Tooltip>
        )}
      </div>
    </TooltipProvider>
  )
}
// ── Exploit Filter ────────────────────────────────────────────────────────
const EXPLOIT_OPTIONS = [
  { value: 'kev',     label: 'KEV (actively exploited)' },
  { value: 'exploit', label: 'Exploit available' },
  { value: 'poc',     label: 'PoC available' },
  { value: 'none',    label: 'No exploit info' },
] as const

function ExploitFilter({ selected, onChange }: { selected: string[]; onChange: (v: string[]) => void }) {
  const [open, setOpen] = useState(false)
  const toggle = (v: string) =>
    onChange(selected.includes(v) ? selected.filter((x) => x !== v) : [...selected, v])
  return (
    <div className="relative">
      <button
        className={`inline-flex items-center gap-1.5 rounded-md border px-2.5 py-1 text-xs font-medium transition-colors hover:bg-muted ${
          selected.length > 0 ? 'border-primary bg-primary/5 text-primary' : 'border-input bg-background'
        }`}
        onClick={() => setOpen((o) => !o)}
      >
        <Zap className="h-3.5 w-3.5" />
        Exploit
        {selected.length > 0 && (
          <span className="ml-0.5 rounded-full bg-primary/20 px-1 text-[10px] font-bold">{selected.length}</span>
        )}
      </button>
      {open && (
        <div className="absolute top-full mt-1 left-0 z-30 bg-popover border rounded-md shadow-md p-2 space-y-1 min-w-[205px]">
          <button className="w-full text-left px-2 py-1.5 text-xs hover:bg-muted rounded" onClick={() => onChange([])}>
            <CheckSquare2 className="inline h-3.5 w-3.5 mr-1.5" />Clear all
          </button>
          <div className="border-t my-1" />
          {EXPLOIT_OPTIONS.map((opt) => (
            <label key={opt.value} className="flex items-center gap-2 rounded px-2 py-1.5 hover:bg-muted cursor-pointer">
              <Checkbox checked={selected.includes(opt.value)} onCheckedChange={() => toggle(opt.value)} className="h-3.5 w-3.5" />
              <span className="text-xs">{opt.label}</span>
            </label>
          ))}
          <button className="w-full text-right px-2 py-1.5 text-xs text-primary hover:underline" onClick={() => setOpen(false)}>Done</button>
        </div>
      )}
    </div>
  )
}

// ── Priority Filter ───────────────────────────────────────────────────────
const PRIORITY_OPTIONS: { value: RiskPriority; label: string; colorClass: string }[] = [
  { value: 'IMMEDIATE',     label: 'Immediate',     colorClass: 'text-red-600' },
  { value: 'HIGH_PRIORITY', label: 'High Priority', colorClass: 'text-orange-600' },
  { value: 'SCHEDULED_FIX', label: 'Scheduled Fix', colorClass: 'text-yellow-600' },
  { value: 'MONITOR',       label: 'Monitor',       colorClass: 'text-blue-600' },
]

function PriorityFilter({ selected, onChange }: { selected: RiskPriority[]; onChange: (v: RiskPriority[]) => void }) {
  const [open, setOpen] = useState(false)
  const toggle = (v: RiskPriority) =>
    onChange(selected.includes(v) ? selected.filter((x) => x !== v) : [...selected, v])
  return (
    <div className="relative">
      <button
        className={`inline-flex items-center gap-1.5 rounded-md border px-2.5 py-1 text-xs font-medium transition-colors hover:bg-muted ${
          selected.length > 0 ? 'border-primary bg-primary/5 text-primary' : 'border-input bg-background'
        }`}
        onClick={() => setOpen((o) => !o)}
      >
        <Flag className="h-3.5 w-3.5" />
        Priority
        {selected.length > 0 && (
          <span className="ml-0.5 rounded-full bg-primary/20 px-1 text-[10px] font-bold">{selected.length}</span>
        )}
      </button>
      {open && (
        <div className="absolute top-full mt-1 left-0 z-30 bg-popover border rounded-md shadow-md p-2 space-y-1 min-w-[170px]">
          <button className="w-full text-left px-2 py-1.5 text-xs hover:bg-muted rounded" onClick={() => onChange([])}>
            <CheckSquare2 className="inline h-3.5 w-3.5 mr-1.5" />Clear all
          </button>
          <div className="border-t my-1" />
          {PRIORITY_OPTIONS.map(({ value, label, colorClass }) => (
            <label key={value} className="flex items-center gap-2 rounded px-2 py-1.5 hover:bg-muted cursor-pointer">
              <Checkbox checked={selected.includes(value)} onCheckedChange={() => toggle(value)} className="h-3.5 w-3.5" />
              <span className={`text-xs font-medium ${colorClass}`}>{label}</span>
            </label>
          ))}
          <button className="w-full text-right px-2 py-1.5 text-xs text-primary hover:underline" onClick={() => setOpen(false)}>Done</button>
        </div>
      )}
    </div>
  )
}

// ── Environment Filter ────────────────────────────────────────────────────
function EnvFilter({
  envs,
  selected,
  onChange,
}: {
  envs: string[]
  selected: string[]
  onChange: (v: string[]) => void
}) {
  const [open, setOpen] = useState(false)
  if (envs.length === 0) return null
  const toggle = (v: string) =>
    onChange(selected.includes(v) ? selected.filter((x) => x !== v) : [...selected, v])
  return (
    <div className="relative">
      <button
        className={`inline-flex items-center gap-1.5 rounded-md border px-2.5 py-1 text-xs font-medium transition-colors hover:bg-muted ${
          selected.length > 0 ? 'border-primary bg-primary/5 text-primary' : 'border-input bg-background'
        }`}
        onClick={() => setOpen((o) => !o)}
      >
        <Globe className="h-3.5 w-3.5" />
        Env
        {selected.length > 0 && (
          <span className="ml-0.5 rounded-full bg-primary/20 px-1 text-[10px] font-bold">{selected.length}</span>
        )}
      </button>
      {open && (
        <div className="absolute top-full mt-1 left-0 z-30 bg-popover border rounded-md shadow-md p-2 space-y-1 min-w-[160px]">
          <button className="w-full text-left px-2 py-1.5 text-xs hover:bg-muted rounded" onClick={() => onChange([])}>
            <CheckSquare2 className="inline h-3.5 w-3.5 mr-1.5" />Clear all
          </button>
          <div className="border-t my-1" />
          {envs.map((e) => (
            <label key={e} className="flex items-center gap-2 rounded px-2 py-1.5 hover:bg-muted cursor-pointer">
              <Checkbox checked={selected.includes(e)} onCheckedChange={() => toggle(e)} className="h-3.5 w-3.5" />
              <span className={`text-xs ${/prod/i.test(e) ? 'font-semibold text-red-600' : ''}`}>{e}</span>
            </label>
          ))}
          <button className="w-full text-right px-2 py-1.5 text-xs text-primary hover:underline" onClick={() => setOpen(false)}>Done</button>
        </div>
      )}
    </div>
  )
}
const colHelper = createColumnHelper<Finding>()

export function FindingsTable() {
  const { findings, setSelectedCVE, cveGroups } = useAppStore()

  const [searchParams, setSearchParams] = useSearchParams()
  const [sorting, setSorting] = useState<SortingState>([{ id: 'riskScore', desc: true }])
  const [copied, setCopied] = useState(false)

  // Filter values derived from URL search params
  const globalFilter = searchParams.get('q') ?? ''
  const severityFilter = useMemo(() => parseList(searchParams.get('sev')) as Severity[], [searchParams])
  const fixStatusFilter = (searchParams.get('fix') ?? 'all') as FixStatus | 'all'
  const envFilter = useMemo(() => parseList(searchParams.get('env')), [searchParams])
  const exploitFilter = useMemo(() => parseList(searchParams.get('exploit')), [searchParams])
  const priorityFilter = useMemo(() => parseList(searchParams.get('priority')) as RiskPriority[], [searchParams])

  function setParam(key: string, value: string | null) {
    setSearchParams((prev) => {
      const next = new URLSearchParams(prev)
      if (!value || value === 'all') next.delete(key)
      else next.set(key, value)
      return next
    }, { replace: true })
  }

  function setListParam(key: string, values: string[]) {
    setSearchParams((prev) => {
      const next = new URLSearchParams(prev)
      if (values.length === 0) next.delete(key)
      else next.set(key, values.join(','))
      return next
    }, { replace: true })
  }

  function clearFilters() {
    setSearchParams({}, { replace: true })
  }

  function copyLink() {
    navigator.clipboard.writeText(window.location.href).then(() => {
      setCopied(true)
      setTimeout(() => setCopied(false), 2000)
    })
  }

  const environments = useMemo(
    () => Array.from(new Set(findings.map((f) => f.environment).filter(Boolean))) as string[],
    [findings],
  )

  const filtered = useMemo(() => {
    const sev = parseList(searchParams.get('sev')) as Severity[]
    const fix = (searchParams.get('fix') ?? 'all') as FixStatus | 'all'
    const env = parseList(searchParams.get('env'))
    const exploit = parseList(searchParams.get('exploit'))
    const priority = parseList(searchParams.get('priority')) as RiskPriority[]
    const q = (searchParams.get('q') ?? '').toLowerCase()

    return findings.filter((f) => {
      if (sev.length > 0 && !sev.includes(f.severity)) return false
      if (fix !== 'all' && getFixStatus(f) !== fix) return false
      if (env.length > 0 && (!f.environment || !env.includes(f.environment))) return false
      if (exploit.length > 0) {
        const hasExploit = !!(f.exploitKnown || f.exploitAvailable || f.exploitPoC)
        const match = exploit.some((ef) => {
          if (ef === 'kev') return !!f.exploitKnown
          if (ef === 'exploit') return !!f.exploitAvailable
          if (ef === 'poc') return !!f.exploitPoC
          if (ef === 'none') return !hasExploit
          return false
        })
        if (!match) return false
      }
      if (priority.length > 0 && (!f.priorityLabel || !priority.includes(f.priorityLabel))) return false
      if (q) {
        return (
          f.cveId.toLowerCase().includes(q) ||
          (f.assetName ?? '').toLowerCase().includes(q) ||
          (f.packageName ?? '').toLowerCase().includes(q) ||
          (f.description ?? '').toLowerCase().includes(q)
        )
      }
      return true
    })
  }, [findings, searchParams])

  const columns = useMemo<ColumnDef<Finding, unknown>[]>(
    () => [
      colHelper.accessor('priorityLabel', {
        id: 'priority',
        header: 'Priority',
        size: 80,
        cell: (info) => {
          const p = info.getValue() as Finding['priorityLabel']
          return p ? <PriorityBadge priority={p} compact /> : null
        },
      }) as ColumnDef<Finding, unknown>,
      colHelper.accessor('riskScore', {
        id: 'riskScore',
        header: ({ column }) => (
          <button
            className="flex items-center gap-1 text-xs font-medium hover:text-foreground"
            onClick={() => column.toggleSorting(column.getIsSorted() === 'asc')}
          >
            Risk <ArrowUpDown className="h-3 w-3" />
          </button>
        ),
        size: 60,
        cell: (info) => {
          const score = info.getValue() as number | undefined
          if (score == null) return <span className="text-muted-foreground text-xs">—</span>
          const color =
            score >= 80 ? 'text-red-600' : score >= 60 ? 'text-orange-500' : score >= 40 ? 'text-yellow-600' : 'text-blue-500'
          return <span className={`text-xs font-bold tabular-nums ${color}`}>{Math.round(score)}</span>
        },
      }) as ColumnDef<Finding, unknown>,
      colHelper.accessor('cveId', {
        id: 'cveId',
        header: 'CVE',
        size: 140,
        cell: (info) => {
          const f = info.row.original
          const group = cveGroups.find((g) => g.cveId === f.cveId)
          return (
            <button
              className="text-left"
              onClick={() => group && setSelectedCVE(group)}
            >
              <div className="font-mono text-xs font-medium text-primary hover:underline">
                {f.cveId}
              </div>
              <ExploitFlags finding={f} />
            </button>
          )
        },
      }) as ColumnDef<Finding, unknown>,
      colHelper.accessor('severity', {
        id: 'severity',
        header: ({ column }) => (
          <button
            className="flex items-center gap-1 text-xs font-medium hover:text-foreground"
            onClick={() => column.toggleSorting(column.getIsSorted() === 'asc')}
          >
            Severity <ArrowUpDown className="h-3 w-3" />
          </button>
        ),
        size: 90,
        cell: (info) => <SeverityBadge severity={info.getValue() as Severity} />,
        sortingFn: (a, b) =>
          SEVERITY_ORDER[a.original.severity] - SEVERITY_ORDER[b.original.severity],
      }) as ColumnDef<Finding, unknown>,
      colHelper.accessor('assetName', {
        id: 'asset',
        header: 'Asset',
        size: 180,
        cell: (info) => {
          const f = info.row.original
          const arn = f.arn ?? ''
          const parsed = parseARN(arn)
          const service = parsed?.service
          return (
            <div className="space-y-0.5">
              <div className="flex items-center gap-1.5">
                {service && <AssetTypeIcon assetType={service} className="h-3.5 w-3.5 text-muted-foreground shrink-0" />}
                <span className="text-xs truncate max-w-[140px]" title={info.getValue() as string ?? ''}>
                  {info.getValue() as string ?? '—'}
                </span>
              </div>
              {f.environment && (
                <span
                  className={`text-[10px] font-medium rounded px-1 py-0.5 ${
                    /prod/i.test(f.environment)
                      ? 'bg-red-100 text-red-700 border border-red-200'
                      : 'text-muted-foreground italic'
                  }`}
                >
                  {f.environment}
                </span>
              )}
            </div>
          )
        },
      }) as ColumnDef<Finding, unknown>,
      colHelper.accessor('packageName', {
        id: 'package',
        header: 'Package',
        size: 150,
        cell: (info) => {
          const f = info.row.original
          return (
            <div className="space-y-0.5">
              <div className="text-xs font-medium truncate max-w-[130px]" title={info.getValue() as string ?? ''}>
                {info.getValue() as string ?? '—'}
              </div>
              {f.installedVersion && (
                <div className="text-[10px] text-muted-foreground tabular-nums">v{f.installedVersion}</div>
              )}
            </div>
          )
        },
      }) as ColumnDef<Finding, unknown>,
      colHelper.accessor('fixedVersion', {
        id: 'fix',
        header: 'Fix',
        size: 130,
        cell: (info) => {
          const f = info.row.original
          const status = getFixStatus(f)
          const showVersion = f.fixedVersion && !['no', 'n/a', 'na', 'none', 'false', '-'].includes(f.fixedVersion.trim().toLowerCase())
          return (
            <div className="space-y-0.5">
              <FixStatusBadge status={status} compact />
              {showVersion && (
                <div className="text-[10px] text-muted-foreground tabular-nums">→ v{f.fixedVersion}</div>
              )}
            </div>
          )
        },
      }) as ColumnDef<Finding, unknown>,
      colHelper.accessor('sla', {
        id: 'sla',
        header: 'SLA',
        size: 90,
        cell: (info) => {
          const v = info.getValue() as string | undefined
          if (!v) return <span className="text-muted-foreground text-xs">—</span>
          const d = new Date(v)
          const isValid = !isNaN(d.getTime())
          if (!isValid) {
            return <span className="text-xs text-muted-foreground">{v}</span>
          }
          const isPast = d < new Date()
          return (
            <span className={`text-xs tabular-nums ${isPast ? 'text-red-600 font-semibold' : 'text-muted-foreground'}`}>
              {d.toLocaleDateString()}
            </span>
          )
        },
      }) as ColumnDef<Finding, unknown>,
    ],
    [cveGroups, setSelectedCVE],
  )

  const table = useReactTable({
    data: filtered,
    columns,
    state: { sorting },
    onSortingChange: setSorting,
    getCoreRowModel: getCoreRowModel(),
    getFilteredRowModel: getFilteredRowModel(),
    getSortedRowModel: getSortedRowModel(),
    getPaginationRowModel: getPaginationRowModel(),
    enableMultiSort: true,
    initialState: { pagination: { pageSize: 25 } },
  })

  const activeFiltersCount =
    (severityFilter.length > 0 ? 1 : 0) +
    (fixStatusFilter !== 'all' ? 1 : 0) +
    (envFilter.length > 0 ? 1 : 0) +
    (exploitFilter.length > 0 ? 1 : 0) +
    (priorityFilter.length > 0 ? 1 : 0) +
    (globalFilter ? 1 : 0)

  return (
    <div className="space-y-3">
      {/* Filter bar */}
      <div className="flex flex-wrap items-center gap-2">
        {/* Search */}
        <div className="relative flex-1 min-w-[200px] max-w-xs">
          <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-muted-foreground" />
          <Input
            placeholder="Search CVE, asset, package…"
            value={globalFilter}
            onChange={(e) => setParam('q', e.target.value || null)}
            className="pl-8 pr-7 h-8 text-xs"
          />
          {globalFilter && (
            <button
              className="absolute right-2 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground"
              onClick={() => setParam('q', null)}
            >
              <X className="h-3.5 w-3.5" />
            </button>
          )}
        </div>

        <SeverityFilter selected={severityFilter} onChange={(v) => setListParam('sev', v)} />

        {/* Fix Status */}
        <Select value={fixStatusFilter} onValueChange={(v) => setParam('fix', v)}>
          <SelectTrigger className="h-8 text-xs w-[135px]">
            <SelectValue placeholder="Fix Status" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All Fix Statuses</SelectItem>
            <SelectItem value="AVAILABLE">Fix Available</SelectItem>
            <SelectItem value="NONE">No Fix</SelectItem>
            <SelectItem value="UNKNOWN">Unknown</SelectItem>
          </SelectContent>
        </Select>

        <ExploitFilter selected={exploitFilter} onChange={(v) => setListParam('exploit', v)} />
        <PriorityFilter selected={priorityFilter} onChange={(v) => setListParam('priority', v)} />
        <EnvFilter envs={environments} selected={envFilter} onChange={(v) => setListParam('env', v)} />

        {/* Clear all */}
        {activeFiltersCount > 0 && (
          <Button
            variant="ghost"
            size="sm"
            className="h-8 gap-1 text-xs text-muted-foreground hover:text-foreground"
            onClick={clearFilters}
          >
            <X className="h-3.5 w-3.5" />
            Clear ({activeFiltersCount})
          </Button>
        )}

        <div className="ml-auto flex items-center gap-2 text-xs text-muted-foreground">
          <span>{filtered.length.toLocaleString()} finding{filtered.length !== 1 ? 's' : ''}</span>
          <Button
            variant="ghost"
            size="icon"
            className="h-6 w-6"
            title="Copy shareable link to current filters"
            onClick={copyLink}
          >
            {copied
              ? <Check className="h-3.5 w-3.5 text-green-600" />
              : <Link2 className="h-3.5 w-3.5" />}
          </Button>
        </div>
      </div>

      {/* Table */}
      <div className="rounded-md border overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-sm min-w-[800px]">
            <thead className="bg-muted/50 border-b">
              {table.getHeaderGroups().map((hg) => (
                <tr key={hg.id}>
                  {hg.headers.map((h) => (
                    <th
                      key={h.id}
                      style={{ width: h.getSize() }}
                      className="px-3 py-2.5 text-left font-medium text-xs text-muted-foreground"
                    >
                      {flexRender(h.column.columnDef.header, h.getContext())}
                    </th>
                  ))}
                </tr>
              ))}
            </thead>
            <tbody>
              {table.getRowModel().rows.length === 0 ? (
                <tr>
                  <td colSpan={columns.length} className="px-4 py-10 text-center text-sm text-muted-foreground">
                    No findings match the current filters.
                  </td>
                </tr>
              ) : (
                table.getRowModel().rows.map((row, i) => (
                  <tr key={row.id} className={`border-t ${i % 2 === 1 ? 'bg-muted/5' : ''} hover:bg-muted/20 transition-colors`}>
                    {row.getVisibleCells().map((cell) => (
                      <td key={cell.id} style={{ width: cell.column.getSize() }} className="px-3 py-2">
                        {flexRender(cell.column.columnDef.cell, cell.getContext())}
                      </td>
                    ))}
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Pagination */}
      <div className="flex items-center justify-between text-xs text-muted-foreground">
        <span>
          Page {table.getState().pagination.pageIndex + 1} of {Math.max(1, table.getPageCount())}
        </span>
        <div className="flex items-center gap-1">
          <Button
            variant="outline"
            size="icon"
            className="h-7 w-7"
            onClick={() => table.previousPage()}
            disabled={!table.getCanPreviousPage()}
          >
            <ChevronLeft className="h-3.5 w-3.5" />
          </Button>
          <Button
            variant="outline"
            size="icon"
            className="h-7 w-7"
            onClick={() => table.nextPage()}
            disabled={!table.getCanNextPage()}
          >
            <ChevronRight className="h-3.5 w-3.5" />
          </Button>
        </div>
      </div>
    </div>
  )
}
