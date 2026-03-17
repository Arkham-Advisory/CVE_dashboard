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
  type ColumnFiltersState,
} from '@tanstack/react-table'
import { ArrowUpDown, ChevronLeft, ChevronRight, Search } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { SeverityBadge } from '@/components/SeverityBadge'
import { useAppStore } from '@/store/useAppStore'
import type { Finding, Severity } from '@/types'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'

const columnHelper = createColumnHelper<Finding>()

export function FindingsTable() {
  const { findings, cveGroups, setSelectedCVE } = useAppStore()
  const [sorting, setSorting] = useState<SortingState>([])
  const [columnFilters, setColumnFilters] = useState<ColumnFiltersState>([])
  const [globalFilter, setGlobalFilter] = useState('')
  const [severityFilter, setSeverityFilter] = useState<string>('all')

  const filteredFindings = useMemo(() => {
    if (severityFilter === 'all') return findings
    return findings.filter((f) => f.severity === severityFilter)
  }, [findings, severityFilter])

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
            CVE ID
            <ArrowUpDown className="ml-1 h-3 w-3" />
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
        header: 'Severity',
        cell: (info) => <SeverityBadge severity={info.getValue() as Severity} />,
      }),
      columnHelper.accessor('assetName', {
        header: 'Asset',
        cell: (info) => (
          <span className="font-mono text-xs max-w-[160px] truncate block" title={info.getValue()}>
            {info.getValue() ?? '—'}
          </span>
        ),
      }),
      columnHelper.accessor('packageName', {
        header: 'Package',
        cell: (info) => (
          <span className="font-mono text-xs">{info.getValue() ?? '—'}</span>
        ),
      }),
      columnHelper.accessor('installedVersion', {
        header: 'Installed',
        cell: (info) => (
          <span className="font-mono text-xs">{info.getValue() ?? '—'}</span>
        ),
      }),
      columnHelper.accessor('fixedVersion', {
        header: 'Fixed',
        cell: (info) => (
          <span className="font-mono text-xs text-green-600">{info.getValue() ?? '—'}</span>
        ),
      }),
      columnHelper.accessor('account', {
        header: 'Account',
        cell: (info) => (
          <span className="text-xs text-muted-foreground">{info.getValue() ?? '—'}</span>
        ),
      }),
      columnHelper.accessor('region', {
        header: 'Region',
        cell: (info) => (
          <span className="text-xs text-muted-foreground">{info.getValue() ?? '—'}</span>
        ),
      }),
    ],
    [cveGroups, setSelectedCVE],
  )

  const table = useReactTable({
    data: filteredFindings,
    columns,
    state: { sorting, columnFilters, globalFilter },
    onSortingChange: setSorting,
    onColumnFiltersChange: setColumnFilters,
    onGlobalFilterChange: setGlobalFilter,
    getCoreRowModel: getCoreRowModel(),
    getSortedRowModel: getSortedRowModel(),
    getFilteredRowModel: getFilteredRowModel(),
    getPaginationRowModel: getPaginationRowModel(),
    initialState: { pagination: { pageSize: 25 } },
  })

  return (
    <div className="space-y-4">
      {/* Filters */}
      <div className="flex flex-col gap-3 sm:flex-row sm:items-center">
        <div className="relative flex-1">
          <Search className="absolute left-2.5 top-2.5 h-4 w-4 text-muted-foreground" />
          <Input
            placeholder="Search findings..."
            value={globalFilter}
            onChange={(e) => setGlobalFilter(e.target.value)}
            className="pl-8"
          />
        </div>
        <Select value={severityFilter} onValueChange={setSeverityFilter}>
          <SelectTrigger className="w-40">
            <SelectValue placeholder="All Severities" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All Severities</SelectItem>
            <SelectItem value="CRITICAL">Critical</SelectItem>
            <SelectItem value="HIGH">High</SelectItem>
            <SelectItem value="MEDIUM">Medium</SelectItem>
            <SelectItem value="LOW">Low</SelectItem>
            <SelectItem value="UNKNOWN">Unknown</SelectItem>
          </SelectContent>
        </Select>
        <span className="text-sm text-muted-foreground whitespace-nowrap">
          {table.getFilteredRowModel().rows.length.toLocaleString()} findings
        </span>
      </div>

      {/* Table */}
      <div className="rounded-md border overflow-x-auto">
        <table className="w-full text-sm">
          <thead className="bg-muted/50">
            {table.getHeaderGroups().map((headerGroup) => (
              <tr key={headerGroup.id}>
                {headerGroup.headers.map((header) => (
                  <th
                    key={header.id}
                    className="text-left px-3 py-2 font-medium text-xs text-muted-foreground whitespace-nowrap"
                  >
                    {header.isPlaceholder
                      ? null
                      : flexRender(header.column.columnDef.header, header.getContext())}
                  </th>
                ))}
              </tr>
            ))}
          </thead>
          <tbody>
            {table.getRowModel().rows.length === 0 ? (
              <tr>
                <td
                  colSpan={columns.length}
                  className="px-3 py-8 text-center text-sm text-muted-foreground"
                >
                  No findings
                </td>
              </tr>
            ) : (
              table.getRowModel().rows.map((row, i) => (
                <tr
                  key={row.id}
                  className={`border-t hover:bg-muted/30 transition-colors ${i % 2 === 0 ? '' : 'bg-muted/10'}`}
                >
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
        <div className="text-xs text-muted-foreground">
          Page {table.getState().pagination.pageIndex + 1} of {table.getPageCount()}
        </div>
        <div className="flex items-center gap-2">
          <Button
            variant="outline"
            size="icon"
            className="h-8 w-8"
            onClick={() => table.previousPage()}
            disabled={!table.getCanPreviousPage()}
          >
            <ChevronLeft className="h-4 w-4" />
          </Button>
          <Button
            variant="outline"
            size="icon"
            className="h-8 w-8"
            onClick={() => table.nextPage()}
            disabled={!table.getCanNextPage()}
          >
            <ChevronRight className="h-4 w-4" />
          </Button>
        </div>
      </div>
    </div>
  )
}
