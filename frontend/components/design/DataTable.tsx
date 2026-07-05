"use client";

import { useMemo, useState } from "react";
import { ArrowDown, ArrowUp, ArrowUpDown, Columns3, Download } from "lucide-react";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import {
  DropdownMenu,
  DropdownMenuCheckboxItem,
  DropdownMenuContent,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { Button, buttonVariants } from "@/components/ui/button";
import { cn } from "@/lib/utils";

export type DataTableColumn<T> = {
  key: string;
  header: string;
  align?: "left" | "right";
  className?: string;
  render: (row: T) => React.ReactNode;
  /** Enables header-click sorting for this column. Requires sortValue since `render` may return JSX. */
  sortable?: boolean;
  sortValue?: (row: T) => string | number;
  /** Value written to the CSV export for this column. Columns without this are omitted from export. */
  csvValue?: (row: T) => string | number;
  /** Set false to keep a column always visible (exempt from the column picker). Defaults to true. */
  hideable?: boolean;
};

function downloadCsv(filename: string, header: string[], rows: (string | number)[][]) {
  const csv = [header, ...rows]
    .map((r) => r.map((v) => `"${String(v).replace(/"/g, '""')}"`).join(","))
    .join("\n");
  const blob = new Blob([csv], { type: "text/csv;charset=utf-8;" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

/** Thin, consistently-styled wrapper over shadcn's table primitives - used anywhere the app
 *  shows tabular data (sessions, scan history, audit logs). Callers own the row data and cell
 *  rendering; this just standardizes header/row chrome so every table in the app matches.
 *
 *  Sorting, the column picker, and CSV export operate on whatever `rows` array is passed in -
 *  for pages that paginate client-side before calling DataTable, that means sort/export apply to
 *  the current page only. Pass the full (pre-pagination) row set if that's not the desired scope. */
export default function DataTable<T>({
  columns,
  rows,
  rowKey,
  emptyLabel = "No data yet.",
  stickyHeader = false,
  maxHeight,
  enableColumnPicker = false,
  enableExport = false,
  exportFilename = "export",
}: {
  columns: DataTableColumn<T>[];
  rows: T[];
  rowKey: (row: T) => string;
  emptyLabel?: string;
  /** Keeps the header row visible while the table body scrolls - useful for long lists like Audit Logs. */
  stickyHeader?: boolean;
  /** Caps the scrollable body height (e.g. "60vh") when stickyHeader is enabled. */
  maxHeight?: string;
  /** Shows a "Columns" dropdown letting the user toggle visibility of hideable columns. */
  enableColumnPicker?: boolean;
  /** Shows an "Export CSV" button that serializes visible columns with a `csvValue`. */
  enableExport?: boolean;
  exportFilename?: string;
}) {
  const [hiddenKeys, setHiddenKeys] = useState<Set<string>>(new Set());
  const [sort, setSort] = useState<{ key: string; direction: "asc" | "desc" } | null>(null);

  const visibleColumns = useMemo(
    () => columns.filter((c) => !hiddenKeys.has(c.key)),
    [columns, hiddenKeys]
  );

  const sortedRows = useMemo(() => {
    if (!sort) return rows;
    const col = columns.find((c) => c.key === sort.key);
    if (!col?.sortValue) return rows;
    const dir = sort.direction === "asc" ? 1 : -1;
    return [...rows].sort((a, b) => {
      const av = col.sortValue!(a);
      const bv = col.sortValue!(b);
      if (av < bv) return -1 * dir;
      if (av > bv) return 1 * dir;
      return 0;
    });
  }, [rows, sort, columns]);

  const toggleSort = (key: string) => {
    setSort((prev) => {
      if (!prev || prev.key !== key) return { key, direction: "asc" };
      if (prev.direction === "asc") return { key, direction: "desc" };
      return null;
    });
  };

  const toggleColumn = (key: string) => {
    setHiddenKeys((prev) => {
      const next = new Set(prev);
      if (next.has(key)) next.delete(key);
      else next.add(key);
      return next;
    });
  };

  const handleExport = () => {
    const exportable = visibleColumns.filter((c) => c.csvValue);
    if (exportable.length === 0) return;
    downloadCsv(
      `${exportFilename}.csv`,
      exportable.map((c) => c.header),
      sortedRows.map((row) => exportable.map((c) => c.csvValue!(row)))
    );
  };

  const showToolbar = enableColumnPicker || enableExport;

  return (
    <div className="rounded-2xl border border-border bg-card overflow-hidden">
      {showToolbar && (
        <div className="flex items-center justify-end gap-2 border-b border-border px-3 py-2">
          {enableColumnPicker && (
            <DropdownMenu>
              <DropdownMenuTrigger
                className={cn(buttonVariants({ variant: "outline", size: "sm" }))}
              >
                <Columns3 size={14} /> Columns
              </DropdownMenuTrigger>
              <DropdownMenuContent align="end" className="w-48">
                <DropdownMenuLabel>Toggle columns</DropdownMenuLabel>
                <DropdownMenuSeparator />
                {columns
                  .filter((c) => c.hideable !== false)
                  .map((c) => (
                    <DropdownMenuCheckboxItem
                      key={c.key}
                      checked={!hiddenKeys.has(c.key)}
                      onCheckedChange={() => toggleColumn(c.key)}
                      onSelect={(e) => e.preventDefault()}
                    >
                      {c.header}
                    </DropdownMenuCheckboxItem>
                  ))}
              </DropdownMenuContent>
            </DropdownMenu>
          )}
          {enableExport && (
            <Button variant="outline" size="sm" onClick={handleExport} disabled={sortedRows.length === 0}>
              <Download size={14} /> Export CSV
            </Button>
          )}
        </div>
      )}
      <div
        className="overflow-x-auto scrollbar-thin"
        style={stickyHeader ? { maxHeight: maxHeight || "60vh", overflowY: "auto" } : undefined}
      >
        <Table>
          <TableHeader className={stickyHeader ? "sticky top-0 z-10 bg-card" : undefined}>
            <TableRow className="hover:bg-transparent">
              {visibleColumns.map((col) => {
                const isSorted = sort?.key === col.key;
                return (
                  <TableHead
                    key={col.key}
                    className={cn(
                      "text-xs uppercase tracking-wide text-muted-foreground",
                      stickyHeader && "bg-card",
                      col.align === "right" && "text-right",
                      col.className
                    )}
                  >
                    {col.sortable && col.sortValue ? (
                      <button
                        type="button"
                        onClick={() => toggleSort(col.key)}
                        className={cn(
                          "inline-flex items-center gap-1 hover:text-foreground",
                          col.align === "right" && "flex-row-reverse"
                        )}
                      >
                        {col.header}
                        {isSorted ? (
                          sort!.direction === "asc" ? (
                            <ArrowUp size={12} />
                          ) : (
                            <ArrowDown size={12} />
                          )
                        ) : (
                          <ArrowUpDown size={12} className="opacity-40" />
                        )}
                      </button>
                    ) : (
                      col.header
                    )}
                  </TableHead>
                );
              })}
            </TableRow>
          </TableHeader>
          <TableBody>
            {sortedRows.length === 0 ? (
              <TableRow>
                <TableCell colSpan={visibleColumns.length} className="py-8 text-center text-sm text-muted-foreground">
                  {emptyLabel}
                </TableCell>
              </TableRow>
            ) : (
              sortedRows.map((row) => (
                <TableRow key={rowKey(row)}>
                  {visibleColumns.map((col) => (
                    <TableCell key={col.key} className={cn(col.align === "right" && "text-right", col.className)}>
                      {col.render(row)}
                    </TableCell>
                  ))}
                </TableRow>
              ))
            )}
          </TableBody>
        </Table>
      </div>
    </div>
  );
}
