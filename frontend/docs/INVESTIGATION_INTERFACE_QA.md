# Investigation Interface QA

## Scope

This note covers the Sprint task set for the analyst-facing alert evidence, investigation controls, correlated activity, and Incident Management v2 interfaces.

## Desktop Readability

Verified by production build and CSS review against common desktop breakpoints:

- 1440px and wider: alert and incident workspaces use a two-column layout with sticky, independently scrollable detail rails.
- 1180px: dashboard/stat/filter grids reduce density while keeping table and detail regions readable.
- 1080px: alert and incident workspaces collapse to one column, preventing narrow side panels.
- 900px and below: shell navigation collapses and detail rails become normal-flow sections.

Relevant responsive rules are in `src/soc/soc.css` for `.alerts-workspace`, `.incident-workspace`, `.alert-detail-column`, `.incident-detail-panel`, and the `max-width: 1180px`, `1080px`, and `900px` media queries.

## Role Behavior

Role restrictions are covered by `tests/permissions.test.js`:

- Admin can mutate investigations and administer the workspace.
- Analyst can mutate investigations but cannot administer the workspace.
- Viewer cannot mutate investigations and cannot administer the workspace.

Route access for role-gated user management is covered by `tests/authRoutes.test.js`.

## Component Coverage

Render-level component coverage is included in `tests/investigationComponents.test.js`:

- Terminal incident confirmation renders the resolution-note control and validation state.
- Non-terminal investigation states do not render the terminal confirmation dialog.
- Evidence pagination renders for large collections and hides for single-page collections.

## Verification Commands

Run from `frontend/`:

```powershell
npm test
npm run build
```
