/** Buckets a list of ISO-date-bearing items into the last N days, so recharts panels can plot
 *  volume-over-time from data the app already fetches (my-files, threat scans, DLP scans, security
 *  events) without needing any new backend endpoint. */
export function bucketByDay<T>(items: T[], getDate: (item: T) => string | Date, days = 14): { date: string; count: number }[] {
  const buckets = new Map<string, number>();
  const today = new Date();
  today.setHours(0, 0, 0, 0);

  for (let i = days - 1; i >= 0; i--) {
    const d = new Date(today);
    d.setDate(d.getDate() - i);
    buckets.set(d.toISOString().slice(0, 10), 0);
  }

  for (const item of items) {
    const raw = getDate(item);
    const d = new Date(raw);
    if (Number.isNaN(d.getTime())) continue;
    d.setHours(0, 0, 0, 0);
    const key = d.toISOString().slice(0, 10);
    if (buckets.has(key)) buckets.set(key, (buckets.get(key) || 0) + 1);
  }

  return Array.from(buckets.entries()).map(([date, count]) => ({
    date: new Date(date).toLocaleDateString(undefined, { month: "short", day: "numeric" }),
    count,
  }));
}

export function toChartArray<T extends string>(record: Record<T, number>): { name: T; value: number }[] {
  return (Object.keys(record) as T[]).map((key) => ({ name: key, value: record[key] }));
}
