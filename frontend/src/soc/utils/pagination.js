export function paginateRecords(records, page, pageSize = 10) {
  const items = Array.isArray(records) ? records : [];
  const safePageSize = Number.isSafeInteger(pageSize) && pageSize > 0 ? pageSize : 10;
  const pageCount = Math.max(1, Math.ceil(items.length / safePageSize));
  const requestedPage = Number.isSafeInteger(page) ? page : Number(page);
  const safePage = Math.min(pageCount, Math.max(1, Number.isFinite(requestedPage) ? Math.trunc(requestedPage) : 1));
  const startIndex = (safePage - 1) * safePageSize;

  return {
    items: items.slice(startIndex, startIndex + safePageSize),
    page: safePage,
    pageCount,
    pageSize: safePageSize,
    start: items.length ? startIndex + 1 : 0,
    end: Math.min(startIndex + safePageSize, items.length),
    total: items.length,
  };
}
