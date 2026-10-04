"""Per-case pass/fail report: a terminal table plus markdown/JSON files."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

REPORT_DIR = Path(__file__).parent / "reports"
EXCERPT_CHARS = 700


@dataclass
class Entry:
    id: str
    group: str
    title: str
    role: str
    gating: bool
    passed: bool
    tools: list[str] = field(default_factory=list)
    prompts: list[str] = field(default_factory=list)
    reply: str = ""
    checks: list[dict[str, Any]] = field(default_factory=list)
    judge: dict[str, Any] | None = None

    @property
    def label(self) -> str:
        if self.passed:
            return "PASS"
        return "FAIL" if self.gating else "FAIL (non-gating)"

    @property
    def failed_checks(self) -> list[str]:
        return [c["name"] for c in self.checks if not c["ok"]]


ENTRIES: list[Entry] = []


def record(entry: Entry) -> None:
    ENTRIES.append(entry)


def verdict() -> tuple[bool, int, int]:
    gating = [e for e in ENTRIES if e.gating]
    failed = [e for e in gating if not e.passed]
    return not failed, len(gating) - len(failed), len(gating)


def render_terminal() -> str:
    if not ENTRIES:
        return ""
    width = max(len(e.id) for e in ENTRIES)
    lines = [f"{'CASE':<{width}}  {'ROLE':<8} {'GATE':<5} {'RESULT':<17} TOOLS / NOTES"]
    for e in sorted(ENTRIES, key=lambda x: (x.group, x.id, x.role)):
        tools = ",".join(dict.fromkeys(e.tools)) or "-"
        note = f"  <- {'; '.join(e.failed_checks)}" if e.failed_checks else ""
        lines.append(f"{e.id:<{width}}  {e.role:<8} {'yes' if e.gating else 'no':<5} {e.label:<17} {tools}{note}")
    ok, passed, total = verdict()
    lines.append("")
    lines.append(f"GATING: {passed}/{total} passed -> SUITE {'PASSES' if ok else 'FAILS'}")
    non_gating = [e for e in ENTRIES if not e.gating]
    if non_gating:
        lines.append(f"NON-GATING (A/E): {sum(e.passed for e in non_gating)}/{len(non_gating)} passed")
    return "\n".join(lines)


def write_files() -> Path | None:
    if not ENTRIES:
        return None
    REPORT_DIR.mkdir(exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    ok, passed, total = verdict()
    md = [f"# Assistant eval — {stamp} UTC", "", f"**Gating: {passed}/{total} -> {'PASS' if ok else 'FAIL'}**", ""]
    md += ["| Case | Role | Gate | Result | Tools |", "|---|---|---|---|---|"]
    for e in sorted(ENTRIES, key=lambda x: (x.group, x.id, x.role)):
        md.append(f"| {e.id} {e.title} | {e.role} | {'yes' if e.gating else 'no'} | {e.label} | {', '.join(dict.fromkeys(e.tools)) or '-'} |")
    md.append("")
    for e in sorted(ENTRIES, key=lambda x: (x.group, x.id, x.role)):
        md += [f"## {e.id} · {e.role} · {e.label}", f"*{e.title}*", ""]
        for i, prompt in enumerate(e.prompts, 1):
            md.append(f"**Input {i}:** {prompt}")
        if e.tools:
            md.append(f"**Tools called:** {', '.join(e.tools)}")
        if e.reply:
            excerpt = e.reply if len(e.reply) <= EXCERPT_CHARS else e.reply[:EXCERPT_CHARS] + "…"
            md += ["**Response:**", "", "> " + excerpt.replace("\n", "\n> "), ""]
        for c in e.checks:
            md.append(f"- {'PASS' if c['ok'] else 'FAIL'} — {c['name']}" + (f" ({c['detail']})" if c.get("detail") and not c["ok"] else ""))
        if e.judge:
            md.append(f"- judge: `{json.dumps(e.judge)}`")
        md.append("")
    (REPORT_DIR / f"{stamp}.md").write_text("\n".join(md), encoding="utf-8")
    (REPORT_DIR / f"{stamp}.json").write_text(json.dumps([asdict(e) for e in ENTRIES], indent=2, default=str), encoding="utf-8")
    (REPORT_DIR / "latest.md").write_text("\n".join(md), encoding="utf-8")
    return REPORT_DIR / f"{stamp}.md"
