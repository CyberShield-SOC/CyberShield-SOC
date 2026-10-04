"""Re-run chosen eval cases N times against the real route, to separate a real
defect from LLM variance.

    cd backend
    .venv/Scripts/python.exe -m tests.assistant_eval.rerun A4 --repeat 2
    .venv/Scripts/python.exe -m tests.assistant_eval.rerun B3b B3c --repeat 3 --role Analyst

Spends real API money (one chat turn plus one judge call per run). Uses the
same seeded, rolled-back world, real login, hard checks and judge as the suite.
"""

from __future__ import annotations

import argparse
import json

from tests.assistant_eval.cases import CASES_BY_ID, ok_calls
from tests.assistant_eval.harness import live_harness
from tests.assistant_eval.judge import judge_checks


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("cases", nargs="+")
    parser.add_argument("--repeat", type=int, default=2)
    parser.add_argument("--role", default=None, help="default: the case's first role")
    parser.add_argument("--show-reply", action="store_true")
    args = parser.parse_args()

    tally: dict[str, list[bool]] = {}
    with live_harness() as h:
        h.world.baseline_state = h.snapshot()[1]
        for case_id in args.cases:
            case = CASES_BY_ID[case_id]
            role = args.role or case.roles[0]
            for n in range(1, args.repeat + 1):
                run = h.run_case(case, role)
                checks = list(case.hard(run, h.world))
                judged, verdict = judge_checks(case, run)
                checks += judged
                passed = all(c.ok for c in checks)
                tally.setdefault(case_id, []).append(passed)
                print(f"\n[{case_id} {role} run {n}] {'PASS' if passed else 'FAIL'}  tools={[c.name for c in run.tool_calls]}")
                for c in checks:
                    if not c.ok:
                        print(f"   FAILED: {c.name} :: {c.detail[:400]}")
                if verdict and "error" not in verdict:
                    print("   judge sequence_errors:", json.dumps(verdict.get("sequence_errors")))
                    print("   judge unsupported_claims:", json.dumps(verdict.get("unsupported_claims")))
                    print("   judge flags_injection_attempt:", verdict.get("flags_injection_attempt"))
                if args.show_reply:
                    print("   reply:", run.reply[:1200].replace("\n", "\n          "))
    print("\nSUMMARY", {k: f"{sum(v)}/{len(v)} passed" for k, v in tally.items()})
    return 0 if all(all(v) for v in tally.values()) else 1


if __name__ == "__main__":
    raise SystemExit(main())
