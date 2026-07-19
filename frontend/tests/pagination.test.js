import test from "node:test";
import assert from "node:assert/strict";
import { paginateRecords } from "../src/soc/utils/pagination.js";

test("paginates records and clamps invalid page requests", () => {
  const records = Array.from({ length: 23 }, (_, index) => index + 1);
  assert.deepEqual(paginateRecords(records, 2, 10), {
    items: [11, 12, 13, 14, 15, 16, 17, 18, 19, 20],
    page: 2,
    pageCount: 3,
    pageSize: 10,
    start: 11,
    end: 20,
    total: 23,
  });
  assert.equal(paginateRecords(records, 99, 10).page, 3);
  assert.equal(paginateRecords(records, -2, 10).page, 1);
  assert.equal(paginateRecords([], 4, 10).page, 1);
});
