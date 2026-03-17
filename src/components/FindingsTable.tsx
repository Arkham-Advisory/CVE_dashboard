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
} from '@tanstack/react-table'
import {
  ArrowUpDown,
  ChevronLeft,
  ChevronRight,
  Search,
  SlidersHorizontal,
  CheckSquare2,
  X,
} from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Badge } from '@/components/ui/badge'
import { SeverityBadge } from '@/components/SeverityBadge'
import { AssetTypeIcon, parseARN } from '@/components/AssetTypeIcon'
import { Checkbox } from '@/components/ui/checkbox'
import { Label } from '@/components/ui/label'
import { Switch } from '@/components/ui/switch'
import { Separator } from '@/components/ui/separator'
import { Popover, PopoverContent, PopoverTrigger } from '@/components/ui/popover'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { useAppStore } from '@/store/useAppStore'
import type { Finding, Severity } from '@/types'
import { ORDERED_SEVERITIES, SEVERITY_ORDER } from '@/types'

const columnHelper = createColumnHelper<Finding>()
const ALL_SEVERITIES: Severity[] = ORDERED_SEVERITIES.filter((s) => s !== 'NONE')

function useDistinct(findings: Finding[], key: keyof Finding): string[] {
  return useMemo(
    () => Array.from(new Set(findings.map((f) => f[key] as string).filter(Boolean))).sort(),
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [findings, key],
  )
}

interface MultiSelectProps {
  label: string
  options: string[]
  selected: string[]
  onChange: (v: string[]) => void
}
function MultiSelectFilter({ label, options, selected, onChange }: MultiSelectProps) {
  const toggle = (v: string) =>
    onChange(selected.includes(v) ? selected.filter((x) => x !== v) : [...selected, v])
  return (
    <Popover>
      <PopoverTrigger asChild>
        <Button variant="outline" size="sm" className="h-9 gap-1.5">
          {label}
          {selected.length > 0 && (
            <Badge variant="secondary" className="h-4 px-1 text-[10px]">
              {selected.length}
            </Badge>
          )}
        </Button>
      </PopoverTrigger>
      <PopoverContent className="w-52 p-2" align="start">
        <div className="space-y-0.5 max-h-56 overflow-y-auto">
          <button
            className="flex w-full items-center gap-2 rounded px-2 py-1.5 text-xs hover:bg-muted"
            onClick={() => onChange([])}
          >
            <CheckSquare2 className="h-3.5 w-3.5" /> All {label}
          </button>
          <Separator className="my-1" />
          {options.map((opt) => (
            <div
              key={opt}
              className="flex items-center gap-2 rounded px-2 py-1.5 hover:bg-muted cursor-pointer"
              onClick={() => toggle(opt)}
            >
              <Checkbox checked={selected.includes(opt)} onCheckedChange={() => toggle(opt)} />
              <span className="text-xs truncate">{opt}</span>
            </div>
          ))}
        </div>
      </PopoverContent>
    </Popover>
  )
}

export function FindingsTable() {
  const { findings, cveGroups, setSelectedCVE } = useAppStore()
  const [sorting, setSorting] = useState<SortingState>([])
  const [globalFilter, setGlobalFilter] = useState('')
  const [severities, setSeverities] = useState<Severity[]>([])
  const [accounts, setAccounts] = useState<string[]>([])
  const [regions, setRegions] = useState<string[]>([])
  const [assetTypes, setAssetTypes] = useState<string[]>([])
  const [hasFix, setHasFix] = useState(false)
  const [pageSize, setPageSize] = useState(25)
  const [cveSearch, setCveSearch] = useState('')
  const [pkgSearch, setPkgSearch] = useState('')

  const distinctAccounts = useMemo(() => {
    // Show accountName labels when available, falling back to account IDs
    const values = new Set<string>()
    for (const f of findings) {
      const label = f.accountName ?? f.account
      if (label) values.add(label)
    }
    return Array.from(values).sort()
  }, [findings])
  const distinctRegions = useDistinct(findings, 'region')
  const distinctAssetTypes = useDistinct(findings, 'assetType')

  const filteredFindings = useMemo(() => {
    return findings.filter((f) => {
      if (severities.length > 0 && !severities.includes(f.severity)) return false
      if (accounts.length > 0) {
        const label = f.accountName ?? f.account ?? ''
        if (!accounts.includes(label)) return false
      }
      if (regions.length > 0 && !regions.includes(f.region ?? '')) return false
      if (assetTypes.length > 0 && !assetTypes.includes(f.assetType ?? '')) return false
      if (hasFix && !f.fixedVersion) return false
      if (cveSearch && !f.cveId.toLowerCase().includes(cveSearch.toLowerCase())) return false
      if (pkgSearch && !(f.packageName ?? '').toLowerCase().includes(pkgSearch.toLowerCase()))
        return false
      return true
    })
  }, [findings, severities, accounts, regions, assetTypes, hasFix, cveSearch, pkgSearch])

  const activeCount =
    severities.length +
    accounts.length +
    regions.length +
    assetTypes.length +
    (hasFix ? 1 : 0) +
    (cveSearch ? 1 : 0) +
    (pkgSearch ? 1 : 0)

  const clearAll = () => {
    setSeverities([])
    setAccounts([])
    setRegions([])
    setAssetTypes([])
    setHasFix(false)
    setCveSearch('')
    setPkgSearch('')
    setGlobalFilter('')
  }

  const columns = useMemo(
    () => [
      columnHelper.accessor('cveId', {
        header: ({ column }) => (
          <Button
            variant="ghost"
            size="sm"
            className="-ml-3 h-8"
            onClick={() => column.toggleSorting(column.getIsSorted() === 'asc')}
          >
            CVE ID <ArrowUpDown className="ml-1 h-3 w-3" />
          </Button>
        ),
        cell: (info) => (
          <button
            className="font-mono text-xs font-medium text-primary hover:underline text-left"
            onClick={() => {
              const group = cveGroups.find((g) => g.cveId === info.getValue())
              if (group) setSelectedCVE(group)
            }}
          >
            {info.getValue()}
          </button>
        ),
      }),
      columnHelper.accessor('severity', {
        header: ({ column }) => (
          <Button
            variant="ghost"
            size="sm"
            className="-ml-3 h-8"
            onClick={() => column.toggleSorting(column.getIsSorted() === 'asc')}
          >
            Severity <ArrowUpDown className="ml-1 h-3 w-3" />
          </Button>
        ),
        sortingFn: (rowA, rowB) =>
          SEVERITY_ORDER[rowA.original.severity as Severity] -
          SEVERITY_ORDER[rowB.original.severity as Severity],
        cell: (info) => <SeverityBadge severity={info.getValue() as Severity} />,
      }),
      columnHelper.accessor('assetName', {
        header: 'Asset',
        cell: (info) => {
          const f = info.row.original
          const arnParsed = f.arn ? parseARN(f.arn) : null
          return (
            <div className="flex items-center gap-1.5 max-w-[180px]">
              <AssetTypeIcon arn={f.arn} assetType={f.assetType} assetName={f.assetName} />
              <div className="min-w-0">
                <div className="font-mono text-xs truncate" title={f.arn ?? f.assetName}>
                  {f.assetName ?? '—'}
                </div>
                {arnParsed && (
                  <div className="text-[10px] text-muted-foreground truncate">
                    {arnParsed.service} · {arnParsed.region || 'global'}
                  </div>
                )}
              </div>
            </div>
          )
        },
      }),
      columnHelper.accessor('assetType', {
        header: 'Type',
        cell: (info) => (
          <span className="text-xs text-muted-foreground">{info.getValue() ?? '—'}</span>
        ),
      }),
      columnHelper.accessor('packageName', {
        header: 'Package',
        cell: (info) => <span className="font-mono text-xs">{info.getValue() ?? '—'}</span>,
      }),
      columnHelper.accessor('installedVersion', {
        header: 'Installed',
        cell: (info) => <span className="font-mono text-xs">{info.getValue() ?? '—'}</span>,
      }),
      columnHelper.accessor('fixedVersion', {
        header: 'Fixed In',
        cell: (info) =>
          info.getValue() ? (
            <span className="font-mono text-xs text-green-600 font-medium">{info.getValue()}</span>
          ) : (
            <span className="text-xs text-muted-foreground">—</span>
          ),
      }),
      columnHelper.accessor('account', {
        header: 'Account',
        cell: (info) => {
          const f = info.row.original
          const displayName = f.accountName ?? f.account
          const titleText = f.accountName ? f.account : undefined // show raw ID on hover only when label is shown
          return displayName ? (
            <span className="text-xs text-muted-foreground" title={titleText}>
              {displayName}
            </span>
          ) : (
            <span className="text-xs text-muted-foreground">—</span>
          )
        },
      }),
      columnHelper.accessor('region', {
        header: 'Region',
        cell: (info) => (
          <span className="text-xs text-muted-foreground">{info.getValue() ?? '—'}</span>
        ),
      }),
      columnHelper.accessor('sla', {
        id: 'sla',
        header: 'SLA / Due',
        cell: (info) => {
          const val = info.getValue()
          if (!val) return <span className="text-xs text-muted-foreground">—</span>
          // Attempt to parse as date for colour coding
          const date = new Date(val)
          const isDate = !isNaN(date.getTime())
          const isBreached = isDate && date < new Date()
          return (
            <span
              className={`text-xs font-mono ${
                isBreached ? 'text-destructive font-semibold' : 'text-muted-foreground'
              }`}
              title={isDate ? date.toLocaleDateString() : undefined}
            >
              {isDate ? date.toLocaleDateString() : val}
            </span>
          )
        },
      }),
    ],
    [cveGroups, setSelectedCVE],
  )

  const table = useReactTable({
    data: filteredFindings,
    columns,
    state: { sorting, globalFilter },
    onSortingChange: setSorting,
    onGlobalFilterChange: setGlobalFilter,
    getCoreRowModel: getCoreRowModel(),
    getSortedRowModel: getSortedRowModel(),
    getFilteredRowModel: getFilteredRowModel(),
    getPaginationRowModel: getPaginationRowModel(),
    initialState: {
      pagination: { pageSize },
      sorting: [{ id: 'severity', desc: false }],
    },
  })

  useMemo(() => { table.setPageSize(pageSize) }, [pageSize]) // eslint-disable-line react-hooks/exhaustive-deps

  return (
    <div className="space-y-4">
      {/* Search row */}
      <div className="flex flex-wrap gap-2">
        <div className="relative flex-1 min-w-[200px]">
          <Search className="absolute left-2.5 top-2.5 h-4 w-4 text-muted-foreground" />
          <Input
            placeholder="Search all columns..."
            value={globalFilter}
            onChange={(e) => setGlobalFilter(e.target.value)}
            className="pl-8"
          />
        </div>
        <Input
          placeholder="CVE ID filter..."
          value={cveSearch}
          onChange={(e) => setCveSearch(e.target.value)}
          className="w-44 font-mono text-xs"
        />
        <Input
          placeholder="Package filter..."
          value={pkgSearch}
          onChange={(e) => setPkgSearch(e.target.value)}
          className="w-36 text-xs"
        />
      </div>

      {/* Filter bar */}
      <div className="flex flex-wrap items-center gap-2">
        <SlidersHorizontal className="h-4 w-4 text-muted-foreground shrink-0" />
        <MultiSelectFilter
          label="Severity"
          options={ALL_SEVERITIES}
          selected={severities}
          onChange={(v) => setSeverities(v as Severity[])}
        />
        {distinctAccounts.length > 0 && (
          <MultiSelectFilter
            label="Account"
            options={distinctAccounts}
            selected={accounts}
            onChange={setAccounts}
          />
        )}
        {distinctRegions.length > 0 && (
          <MultiSelectFilter
            label="Region"
            options={distinctRegions}
            selected={regions}
            onChange={setRegions}
          />
        )}
        {distinctAssetTypes.length > 0 && (
          <MultiSelectFilter
            label="Asset Type"
            options={distinctAssetTypes}
            selected={assetTypes}
            onChange={setAssetTypes}
          />
        )}
        <div className="flex items-center gap-2 rounded-md border px-3 h-9">
          <Label className="text-xs cursor-pointer whitespace-nowrap">Has Fix</Label>
          <Switch checked={hasFix} onCheckedChange={setHasFix} />
        </div>
        {activeCount > 0 && (
          <Button variant="ghost" size="sm" className="h-9 gap-1 text-muted-foreground" onClick={clearAll}>
            <X className="h-3.5 w-3.5" /> Clear {activeCount}
          </Button>
        )}
        <div className="ml-auto flex items-center gap-2">
          <span className="text-xs text-muted-foreground whitespace-nowrap">
            {table.getFilteredRowModel().rows.length.toLocaleString()} rows
          </span>
          <Select value={String(pageSize)} onValueChange={(v) => setPageSize(Number(v))}>
            <SelectTrigger className="h-9 w-20 text-xs">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              {[10, 25, 50, 100].map((n) => (
                <SelectItem key={n} value={String(n)} className="text-xs">
                  {n} / page
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>
      </div>

      {/* Active chips */}
      {activeCount > 0 && (
        <div className="flex flex-wrap gap-1.5">
          {severities.map((s) => (
            <Badge
              key={s}
              variant="secondary"
              className="gap-1 cursor-pointer"
              onClick={() => setSeverities(severities.filter((x) => x !== s))}
            >
              {s} <X className="h-3 w-3" />
            </Badge>
          ))}
          {[...accounts, ...regions, ...assetTypes].map((v) => (
            <Badge
              key={v}
              variant="secondary"
              className="gap-1 cursor-pointer"
              onClick={() => {
                setAccounts(accounts.filter((x) => x !== v))
                setRegions(regions.filter((x) => x !== v))
                setAssetTypes(assetTypes.filter((x) => x !== v))
              }}
            >
              {v} <X className="h-3 w-3" />
            </Badge>
          ))}
          {hasFix && (
            <Badge variant="secondary" className="gap-1 cursor-pointer" onClick={() => setHasFix(false)}>
              Has Fix <X className="h-3 w-3" />
            </Badge>
          )}
        </div>
      )}

      {/* Table */}
      <div className="rounded-md border overflow-x-auto">
        <table className="w-full text-sm">
          <thead className="bg-muted/50">
            {table.getHeaderGroups().map((hg) => (
              <tr key={hg.id}>
                {hg.headers.map((h) => (
                  <th key={h.id} className="text-left px-3 py-2 font-medium text-xs text-muted-foreground whitespace-nowrap">
                    {h.isPlaceholder ? null : flexRender(h.column.columnDef.header, h.getContext())}
                  </th>
                ))}
              </tr>
            ))}
          </thead>
          <tbody>
            {table.getRowModel().rows.length === 0 ? (
              <tr>
                <td colSpan={columns.length} className="px-3 py-10 text-center text-sm text-muted-foreground">
                  No findings match the current filters
                </td>
              </tr>
            ) : (
              table.getRowModel().rows.map((row, i) => (
                <tr key={row.id} className={`border-t hover:bg-muted/30 transition-colors ${i % 2 ? 'bg-muted/10' : ''}`}>
                  {row.getVisibleCells().map((cell) => (
                    <td key={cell.id} className="px-3 py-2">
                      {flexRender(cell.column.columnDef.cell, cell.getContext())}
                    </td>
                  ))}
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>

      {/* Pagination */}
      <div className="flex items-center justify-between">
        <span className="text-xs text-muted-foreground">
          Page {table.getState().pagination.pageIndex + 1} of {Math.max(1, table.getPageCount())}
        </span>
        <div className="flex items-center gap-1">
          {[
            { label: '«', action: () => table.setPageIndex(0), disabled: !table.getCanPreviousPage() },
            { label: <ChevronLeft className="h-4 w-4" />, action: () => table.previousPage(), disabled: !table.getCanPreviousPage() },
            { label: <ChevronRight className="h-4 w-4" />, action: () => table.nextPage(), disabled: !table.getCanNextPage() },
            { label: '»', action: () => table.setPageIndex(table.getPageCount() - 1), disabled: !table.getCanNextPage() },
          ].map((btn, i) => (
            <Button key={i} variant="outline" size="icon" className="h-8 w-8" onClick={btn.action} disabled={btn.disabled}>
              {btn.label}
            </Button>
          ))}
        </div>
      </div>
    </div>
  )
}
