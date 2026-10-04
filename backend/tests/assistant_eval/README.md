# AI Assistant eval: run guide

Live eval of the read-only AI assistant. It drives the real `POST /assistant/chat`
route with real logins as Viewer, Analyst and Admin, against the real Claude API,
inside a rolled-back database transaction.

**Full reference (cases, gating, how the hard gates work, known gaps, latest
results): [`docs/assistant-eval.md`](../../../docs/assistant-eval.md).**

## Run

From `backend/`:

```
RUN_ASSISTANT_EVAL=1 .venv/Scripts/python.exe -m pytest tests/assistant_eval -q -rx
```

- Needs `ANTHROPIC_API_KEY` in `.env` and the database up at the Alembic head.
- Without `RUN_ASSISTANT_EVAL=1` this directory is not collected, so a normal
  `pytest tests` run (and CI) is unchanged and costs nothing.
- A full run makes about 35 chat turns plus about 28 judge calls and takes about
  8 minutes.
- Reports land in `reports/` (gitignored): `latest.md` plus a timestamped `.md`
  and `.json`.

Re-run chosen cases to separate a real defect from LLM variance:

```
.venv/Scripts/python.exe -m tests.assistant_eval.rerun A4b --repeat 3
.venv/Scripts/python.exe -m tests.assistant_eval.rerun B3b B3c --repeat 3 --role Analyst
```

## Layout

| File | Role |
|---|---|
| `harness.py` | fixtures, real login, recording of tool calls / SQL / DB digests |
| `cases.py` | case definitions and their code-only checks |
| `judge.py` | LLM judge (`claude-sonnet-5-5`) for the soft criteria |
| `test_assistant_eval.py` | the pytest entry point |
| `report.py` | terminal table and markdown/JSON report |
| `rerun.py` | repeat selected cases N times |

The checks that prove the hard gates can fail live in
`backend/tests/test_assistant_eval_machinery.py` and run in the default suite.
