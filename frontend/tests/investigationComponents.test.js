import test from "node:test";
import assert from "node:assert/strict";
import React from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { createServer } from "vite";

let viteServer;

async function loadComponents() {
  if (!viteServer) {
    viteServer = await createServer({
      appType: "custom",
      logLevel: "silent",
      server: { middlewareMode: true },
    });
  }
  const dialogModule = await viteServer.ssrLoadModule("/src/soc/components/IncidentStatusConfirmDialog.jsx");
  const uiModule = await viteServer.ssrLoadModule("/src/soc/components/Ui.jsx");
  return {
    IncidentStatusConfirmDialog: dialogModule.default,
    TablePagination: uiModule.TablePagination,
  };
}

test.after(async () => {
  if (viteServer) await viteServer.close();
});

test("renders terminal incident confirmation with a required resolution note field", async () => {
  const { IncidentStatusConfirmDialog } = await loadComponents();
  const html = renderToStaticMarkup(
    React.createElement(IncidentStatusConfirmDialog, {
      disabled: false,
      incident: { id: "INC-1042", title: "Brute-force SSH attack" },
      status: "resolved",
      resolutionNote: "",
      resolutionError: "Add at least 12 characters explaining the final decision.",
      onCancel: () => {},
      onConfirm: () => {},
      onResolutionNoteChange: () => {},
    }),
  );

  assert.match(html, /Resolve this incident\?/);
  assert.match(html, /INC-1042 · Brute-force SSH attack/);
  assert.match(html, /Resolution note/);
  assert.match(html, /aria-invalid="true"/);
  assert.match(html, /Add at least 12 characters/);
});

test("hides terminal incident confirmation for non-terminal investigation states", async () => {
  const { IncidentStatusConfirmDialog } = await loadComponents();
  const html = renderToStaticMarkup(
    React.createElement(IncidentStatusConfirmDialog, {
      disabled: false,
      incident: { id: "INC-1042", title: "Brute-force SSH attack" },
      status: "investigating",
      onCancel: () => {},
      onConfirm: () => {},
    }),
  );

  assert.equal(html, "");
});

test("renders evidence pagination controls only for multi-page collections", async () => {
  const { TablePagination } = await loadComponents();
  const html = renderToStaticMarkup(
    React.createElement(TablePagination, {
      label: "evidence records",
      page: 2,
      pageSize: 4,
      totalItems: 11,
      onPageChange: () => {},
    }),
  );

  assert.match(html, /5–8 of 11/);
  assert.match(html, /evidence records pagination/);
  assert.match(html, /Previous/);
  assert.match(html, /Next/);

  const hidden = renderToStaticMarkup(
    React.createElement(TablePagination, {
      label: "evidence records",
      page: 1,
      pageSize: 4,
      totalItems: 4,
      onPageChange: () => {},
    }),
  );
  assert.equal(hidden, "");
});
