# Cleanup Audit — 2026-10-01

Report only as originally written below. Nothing in this repo was deleted or
modified while producing the original audit.
Scope: `backend/`, `frontend/`, `parser/`, `ml_experiments/`, `docs/`, `sample-logs/`,
and deployment config at the repo root.

**Status update (2026-10-01): all items acted on, team-approved.** Every
"needs a decision" item and the ruff/doc fixes below are now done — see the
inline ✅ notes on each item and the updated Summary at the bottom. Two
commits: one for the original ruff/doc/CSV cleanup, one for the
team-approved `create_or_update_blocked_ip` removal, `nixpacks.toml`
deletion, and frontend audit-doc archiving.

Tools used: `ruff check --select F401,F841` (backend/parser/ml_experiments),
`vulture --min-confidence 80` (same scope), `npx knip` (frontend), plus manual
grep/read passes for duplicate logic, unused deps, and leftover files.

---

## Safe to remove

Nothing in this audit reached "remove with no further input" confidence — every
unused-looking item either turned out to be real (if small) dead code that's
worth a one-line fix rather than deletion, or had enough ambiguity (sample
data, deployment config) that it belongs in "needs a decision" instead. The
nine ruff/vulture findings below are the closest thing to safe removals; they
are genuinely dead code, not leftover files, so I'd fix them in a small
cleanup commit rather than batch-delete anything.

### Unused imports/variables (ruff F401/F841) — high confidence, all 13
| File:Line | Finding |
|---|---|
| `backend/app/models/blocked_ip.py:4` | `sqlalchemy.Text`, `sqlalchemy.UniqueConstraint` imported, unused |
| `backend/app/parsers/apache_parser.py:2` | `datetime.timezone` imported, unused |
| `backend/app/repositories/custom_rule_repository.py:5` | `sqlalchemy.func` imported, unused |
| `backend/main.py:3` | `from app.main import app` imported, unused (also flagged by vulture) |
| `backend/tests/test_detection.py:12` | `Alert` imported, unused |
| `backend/tests/test_detection_edge_cases.py:149` | `rule` assigned, never read |
| `backend/tests/test_ml_behavioral_anomaly.py:25` | `get_baseline` imported, unused |
| `backend/tests/test_ml_egress_volume.py:7` | `timedelta` imported, unused |
| `backend/tests/test_ml_models_api.py:96` | `admin` assigned, never read |
| `backend/tests/test_password_reset.py:24` | `settings` imported, unused |
| `backend/tests/test_rbac_privilege_escalation.py:100,158` | `analyst_role` assigned, never read (×2) |

All confirmed by reading each file — no dynamic use (no `__all__` re-export,
no reflection). 9 of the 13 are mechanically fixable with `ruff --fix`; the
`F841` ones need the assignment line removed by hand since the right-hand
side may have side effects (it doesn't, in all four cases — `ensure_role`,
`as_role`, and `PortScanRule(...)` are all side-effect-free constructors, but
worth a human glance before auto-removing the line, not just the name).

**✅ Done.** All 13 fixed (imports removed; `F841` assignments dropped while
keeping the side-effecting calls `ensure_role(...)`/`as_role(...)` where
applicable). `ruff check --select F401,F841` now passes clean on
`app/`, `tests/`, and `main.py`. Full backend suite re-run: 549/549 passing.

### Dead function parameter (vulture, 100% confidence)
- `backend/app/repositories/blocked_ip_repository.py:50` — `is_automatic: bool = True`
  parameter on `create_or_update_blocked_ip` is never read inside the
  function body, and the function itself is called nowhere in `app/`
  (only in its own test, `backend/tests/test_blocked_ip_repository.py`).
  The real call path (`upload.py` → `auto_block_from_alerts` →
  `bulk_create_or_update_blocked_ips`) never calls this single-row function
  at all. This isn't just an unused parameter — the whole function looks
  vestigial from before the batched upsert existed. **Needs a decision**
  rather than a blind delete because its test would need to go with it,
  and I want you to confirm there's no planned caller (e.g. a future
  manual single-IP block endpoint) before I touch it. Moved to that
  section below instead of here.

---

## Needs a decision

### 1. `backend/app/repositories/blocked_ip_repository.py:50-61` — `create_or_update_blocked_ip`
Unused in production code (see above); only referenced by its own test.
Confidence: medium-high that it's dead, but deleting it means also deleting
or rewriting `backend/tests/test_blocked_ip_repository.py`, which per your
instructions I won't do without approval. Options: (a) delete both function
and test if there's truly no planned single-IP-block caller, or (b) keep as
a small public API for a future manual-block feature and just drop the
unused `is_automatic` param.

**✅ Done, with a correction.** Re-searched for all references before
removing: `create_or_update_blocked_ip` was called nowhere outside its own
definition and two docstring mentions — not even by
`backend/tests/test_blocked_ip_repository.py`. That file's module docstring
*mentions* the old function by name for historical narrative ("the old
select-then-insert ... had no way to see an uncommitted duplicate"), but
every actual test in it exercises `auto_block_from_alerts` and
`bulk_create_or_update_blocked_ips` — real, still-used regression coverage
for a production dedup bug fix, unrelated to the function being removed.
So "its test" didn't exist as a separate thing to delete. Removed the
function and its now-dangling docstring cross-reference in
`_upsert_blocked_ips_statement`, reworded the historical mention in the
test file's docstring to not name a function that no longer exists, and
left the rest of `test_blocked_ip_repository.py` untouched.

### 2. `nixpacks.toml` (repo root) — likely superseded deploy config
`railway.json` explicitly sets `"builder": "DOCKERFILE"`, and `Dockerfile`
already performs the exact same steps `nixpacks.toml` describes (install
backend deps, `npm ci`/`npm run build` for frontend, `alembic upgrade head`
then `uvicorn` on `$PORT`). With the builder pinned to `DOCKERFILE`, Railway
should never read `nixpacks.toml`. Confidence: medium — I did not verify
against Railway's actual current build logs, only the static config, so
there's a chance some other part of the deploy pipeline still looks at it.
**Flagging, not removing**, since deployment config is high-blast-radius if
I'm wrong about which builder is actually active.

**✅ Done.** Re-confirmed `railway.json`'s `"builder": "DOCKERFILE"` and
grepped the whole repo (outside `.git/`, `node_modules/`) for "nixpacks":
the only other hits were this report and two docs
(`docs/deployment_and_documentation.md`, which described `nixpacks.toml` as
an active config file and has been corrected to describe `railway.json` +
`Dockerfile` only; `docs/ml/isolation_forest_feasibility.md`, which only
mentions "Railway/nixpacks build time" generically and wasn't touched since
it isn't describing the file itself). Deleted `nixpacks.toml`.

### 3. `sample-logs/converted_log_csv_files/` (6 files)
CSV re-exports of the same five scenarios already covered by
`sample-logs/cybershield-rule-tests/*.log` (confirmed by diffing
`01_brute_force_login.csv` against `01_brute_force_login.log` — same
timestamps/IPs/messages, just wrapped in a structured CSV with a
`raw_message` column) plus one extra `all_logs_combined.csv`. Not
referenced by any test, script, README, or doc anywhere in the repo
(checked `docs/`, `README.md`, both `sample-logs/*/README*` files, and
`frontend/`). Everything else in `sample-logs/` is explicitly documented
as manual-upload demo fixtures (see "Keep" section) — this is the one
subfolder with no such documentation and no automated reference.
Confidence: medium-high it's a leftover from an earlier log→CSV
conversion experiment. Low risk to remove (it's inert data, nothing can
dynamically import it), but I'm not certain you don't use it for manual
CSV-parser spot-checks outside the repo's documented workflows.

**✅ Done.** `git log --format="%an %ad %s" -- sample-logs/converted_log_csv_files/`
showed it was added by Yugal99 on Sun Sep 13 2026 15:57:45 -0500, bundled
into the "Complete Sprint 5 technical tasks and Railway configuration"
commit rather than added as its own change. Deleted via `git rm -r`.

### 4. `frontend/docs/FRONTEND_AUDIT.md` and `frontend/docs/INTERACTION_TEST_REPORT.md`
Both are dated, point-in-time snapshot reports ("Frontend audit — July 18,
2026", "Audit date: July 17, 2026") sitting alongside living reference docs
(`ARCHITECTURE.md`, `BACKEND_CONTRACT.md`, `CONNECTED_BACKEND.md`,
`WORKFLOW_VALIDATION.md`) that aren't dated and describe current behavior.
Confidence: low-medium that these are "unnecessary" — they may be
intentional historical records (e.g., sprint/DDS deliverables), similar to
the `docs/sprint2_*.md` and `docs/kapil_sprint5_dds.md` files at the repo
root, which I'm treating as intentionally-kept project history, not cruft.
Flagging only because, unlike the sprint-numbered docs, these two don't
carry a sprint/author label that signals "historical snapshot" to a new
reader — worth either renaming to make that obvious or archiving under a
`docs/archive/` folder if you want to keep them.

**✅ Done.** Moved both via `git mv` into `frontend/docs/archive/`. Updated
the two places that linked to `INTERACTION_TEST_REPORT.md` by its old path:
`README.md`'s frontend-documentation list (now labeled "Interaction test
report (archived)") and `frontend/docs/WORKFLOW_VALIDATION.md`'s
cross-reference. `FRONTEND_AUDIT.md` had no inbound links to fix.

### 5. `docs/ml/isolation_forest_feasibility.md:304` — stale rule count
Says "the other 28 rules"; the engine currently registers 31. Harmless
(it's describing historical context at the time of the feasibility study),
but worth a one-line update if you want the doc to read as current rather
than dated.

**✅ Done.** Updated both occurrences ("28 rule-based detectors" in the
opening summary at line 4, and "the other 28 rules" at line 304) to 31.

---

## Keep

- **`parser/log_parser.py`** vs **`backend/app/parsers/log_parser.py`** —
  look like the duplicate-parser case you flagged, but they're not: the
  root-level file is explicitly documented in `README.md` ("## Run the
  Standalone Parser Script... legacy standalone CLI utility kept for quick,
  dependency-free parsing... The live backend uses its own parser
  (`backend/app/parsers/`), not this script.") as an intentionally-kept,
  separate tool. The backend one is a format-dispatch module
  (`parse_log()` routes to apache/syslog/auditd/csv/json/generic parsers);
  the root one is a self-contained regex-based CLI with its own JSON/CSV
  output. No code imports the root file from the backend or vice versa.
  Functionally redundant in *purpose* (both parse auth-style logs) but not
  duplicated in *code* — nothing to merge or delete without a product
  decision to drop the standalone CLI entirely, which is outside this
  audit's scope.

- **`sample-logs/*.log`, `*.csv` at the top level, and
  `sample-logs/cybershield-rule-tests/`** — not referenced by any automated
  test (confirmed: `backend/tests/test_sample_logs_e2e.py` only reads from
  `sample-logs/detection/`), but every one of these is explicitly documented
  as a manual-upload demo fixture for exercising a specific detection rule
  through the UI (`sample-logs/NEW_RULES_README.txt` lists all 22,
  `sample-logs/cybershield-rule-tests/README.txt` lists the original 8,
  each with expected alert output verified against the real engine). This
  is intentional demo/QA tooling, not accidental leftovers — "unreferenced
  by code" isn't the same as "unused" here since the whole point is manual
  upload. Did not touch.

  *Update 2026-10-04:* three top-level fixtures were deleted because they had
  no code, test, loader, or doc consumers beyond their own upload
  instructions: `egress_volume_anomaly.csv`, `behavioral_anomaly_login.csv`,
  and `behavioral_anomaly_egress.csv`. Their entries in
  `NEW_RULES_README.txt` (#5, #21, #22) now read "REMOVED" and keep their
  numbers, so the other entries' numbering is unchanged. The remaining
  fixtures are untouched.

- **`ml_experiments/` scripts, models, and `reports/*.txt`** — all cited by
  name in `ml_experiments/README.md`'s section-by-section validation
  narrative. `models/` is gitignored and not in the repo; the `.txt`
  reports under version control are the evidence trail the README
  references. Keep as-is.

- **Backend dependencies (`requirements.txt`)** — checked every entry for a
  direct `import`; `httpx`, `psycopg`, and `python-multipart` showed zero
  direct imports but are used indirectly (`httpx` backs FastAPI's
  `TestClient` used in 19 test files; `psycopg` is loaded by SQLAlchemy via
  the `postgresql+psycopg://` connection string, never imported by name;
  `python-multipart` is required by FastAPI for `UploadFile`/form parsing).
  No unused dependencies found.

- **Frontend dependencies (`package.json`)** — only 3 runtime deps (`react`,
  `react-dom`, `lucide-react`) and 4 dev deps (Vite, Tailwind, the Vite
  React plugin); `knip` found zero unused files and zero unused
  dependencies. No findings.

- **Alembic migrations (`backend/alembic/versions/`, 21 files)** and **all
  pytest fixtures/conftest.py** — excluded from consideration per your
  instructions regardless of apparent usage.

---

## Frontend: unused exports (knip), for awareness only

`knip` found 0 unused files and 0 unused dependencies, but flagged 15
exported symbols with no importer anywhere in `frontend/src` or
`frontend/tests`. These are exports, not dead code necessarily — several
look like a public surface kept for symmetry (e.g. paired error-message
getters) or for an upcoming consumer. Listing for awareness; none are
acted on without your input:

| Export | File |
|---|---|
| `getTwoFactorFailureMessage` | `src/services/authClient.js:42` |
| `getPasswordResetRequestFailureMessage` | `src/services/authClient.js:69` |
| `getPasswordResetFailureMessage` | `src/services/authClient.js:76` |
| `PasswordStrengthMeter` | `src/soc/components/PasswordField.jsx:50` |
| `RULE_CATEGORY_VALUES` | `src/soc/data/ruleCategories.js:34` |
| `isRuleCategory` | `src/soc/data/ruleCategories.js:46` |
| `normalizeThreatFeed` | `src/soc/services/socRepository.js:278` |
| `normalizeHostHeartbeat` | `src/soc/services/socRepository.js:290` |
| `normalizeBuiltInRule` | `src/soc/services/socRepository.js:457` |
| `PASSWORD_SPECIAL_CHARACTERS` | `src/soc/utils/passwordPolicy.js:16` |
| `PASSWORD_REQUIREMENTS` | `src/soc/utils/passwordPolicy.js:23` |
| `CONFIG_FIELDS` | `src/soc/utils/ruleConfig.js:8` |
| `fieldLabel` | `src/soc/utils/ruleConfig.js:192` |
| `recordTimestamp` | `src/soc/utils/timeRange.js:23` |
| `SOC_ROLES` | `src/utils/permissions.js:2` |

Several of these (`normalizeThreatFeed`, `normalizeHostHeartbeat`,
`normalizeBuiltInRule`) are named like internal normalizers in a repository
module — worth checking whether they're exported only for unit tests that
knip's default config doesn't count as "used," rather than truly dead;
I did not dig into each one's test coverage individually.

---

## What I didn't flag

- No duplicate helper logic found between `frontend/src/utils/` and
  `frontend/src/soc/utils/` — the split is a real app-wide-vs-SOC-feature
  boundary, not an accidental fork (compared all exported function names
  across both directories; no name or logic overlap).
- No duplicate Python logic found across `backend/app/parsers/*.py`,
  `backend/app/detection/rules/*.py`, or `backend/app/repositories/*.py`
  beyond what's listed above.
- `backend/scripts/run_detection.py` is a real, working dev CLI
  (uses the production parser + `DetectionEngine` directly) but isn't
  mentioned in `README.md` the way `scripts/check_db.py` and
  `parser/log_parser.py` are. Not a cleanup item, just a minor doc gap if
  you want it discoverable.

---

## Summary

- **Safe to remove:** 0 files/items reached that bar on their own merits;
  the 13 ruff findings were safe *fixes* (strip an import/assignment), not
  file removals. ✅ Fixed.
- **Needs a decision:** 5 items — `create_or_update_blocked_ip`,
  `nixpacks.toml`, `sample-logs/converted_log_csv_files/`,
  the two dated frontend audit docs, and one stale rule-count line in a doc.
  ✅ All 5 acted on (team-approved 2026-10-01) — see inline notes above.
  One correction along the way: `create_or_update_blocked_ip` turned out to
  have no dedicated test to remove alongside it; only the dead function
  itself was removed.
- **Keep:** everything else audited, including the "looks like a duplicate
  parser" case, all `sample-logs/` demo fixtures, `ml_experiments/`,
  Alembic migrations, test fixtures, and all current dependencies. Still
  untouched.

## Status: closed

All items resolved as of 2026-10-01. Two commits: ruff/doc/CSV cleanup, and
the team-approved `blocked_ip_repository`/`nixpacks.toml`/archive changes.
Full backend (549 tests) and frontend (110 tests) suites plus `npm run
build` were re-verified green after both commits.
