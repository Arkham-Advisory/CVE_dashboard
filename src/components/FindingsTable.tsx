import { useState, useMemo } from 'react'
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
import type { Finding, Severity, FixStatus } from '@/types'
import { SEVERITY_ORDER } from '@/types'

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

const colHelper = createColumnHelper<Finding>()

export function FindingsTable() {
  const { findings, setSelectedCVE, cveGroups } = useAppStore()

  const [globalFilter, setGlobalFilter] = useState('')
  const [severityFilter, setSeverityFilter] = useState<Severity[]>([])
  const [fixStatusFilter, setFixStatusFilter] = useState<FixStatus | 'all'>('all')
  const [envFilter, setEnvFilter] = useState<string[]>([])
  const [sorting, setSorting] = useState<SortingState>([{ id: 'riskScore', desc: true }])

  const environments = useMemo(
    () => Array.from(new Set(findings.map((f) => f.environment).filter(Boolean))) as string[],
    [findings],
  )

  const filtered = useMemo(() => {
    return findings.filter((f) => {
      if (severityFilter.length > 0 && !severityFilter.includes(f.severity)) return false
      if (fixStatusFilter !== 'all' && getFixStatus(f) !== fixStatusFilter) return false
      if (envFilter.length > 0 && (!f.environment || !envFilter.includes(f.environment))) return false
      if (globalFilter) {
        const q = globalFilter.toLowerCase()
        return (
          f.cveId.toLowerCase().includes(q) ||
          (f.assetName ?? '').toLowerCase().includes(q) ||
          (f.packageName ?? '').toLowerCase().includes(q) ||
          (f.description ?? '').toLowerCase().includes(q)
        )
      }
      return true
    })
  }, [findings, globalFilter, severityFilter, fixStatusFilter, envFilter])

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
    (envFilter.length > 0 ? 1 : 0)

  return (
    <div className="space-y-3">
      {/* Filter bar */}
      <div className="flex flex-wrap items-center gap-2">
        <div className="relative flex-1 min-w-[200px] max-w-xs">
          <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-muted-foreground" />
          <Input
            placeholder="Search CVE, asset, package…"
            value={globalFilter}
            onChange={(e) => setGlobalFilter(e.target.value)}
            className="pl-8 h-8 text-xs"
          />
        </div>

        <SeverityFilter selected={severityFilter} onChange={setSeverityFilter} />

        {/* Fix Status filter */}
        <Select
          value={fixStatusFilter}
          onValueChange={(v) => setFixStatusFilter(v as FixStatus | 'all')}
        >
          <SelectTrigger className="h-8 text-xs w-[140px]">
            <SelectValue placeholder="Fix Status" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All Fix Statuses</SelectItem>
            <SelectItem value="AVAILABLE">Fix Available</SelectItem>
            <SelectItem value="NONE">No Fix Available</SelectItem>
            <SelectItem value="UNKNOWN">Unknown</SelectItem>
          </SelectContent>
        </Select>

        {/* Environment filter */}
        {environments.length > 0 && (
          <Select
            value={envFilter[0] ?? 'all'}
            onValueChange={(v) => setEnvFilter(v === 'all' ? [] : [v])}
          >
            <SelectTrigger className="h-8 text-xs w-[130px]">
              <SelectValue placeholder="Environment" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="all">All Environments</SelectItem>
              {environments.map((e) => (
                <SelectItem key={e} value={e}>{e}</SelectItem>
              ))}
            </SelectContent>
          </Select>
        )}

        {/* Clear filters */}
        {activeFiltersCount > 0 && (
          <Button
            variant="ghost"
            size="sm"
            className="h-8 gap-1 text-xs text-muted-foreground hover:text-foreground"
            onClick={() => {
              setSeverityFilter([])
              setFixStatusFilter('all')
              setEnvFilter([])
            }}
          >
            <X className="h-3.5 w-3.5" />
            Clear ({activeFiltersCount})
          </Button>
        )}

        <div className="ml-auto text-xs text-muted-foreground">
          {filtered.length.toLocaleString()} finding{filtered.length !== 1 ? 's' : ''}
        </div>
      </div>

      <p className="text-[11px] text-muted-foreground italic">
        Findings without a fix are always shown. Use the Fix Status filter above to view them specifically.
      </p>

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
