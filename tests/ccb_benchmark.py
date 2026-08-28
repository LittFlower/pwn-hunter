"""Run PwnHunter against the local CCB Final 2026 pwn corpus.

Only independently reviewed roots are used as required hits.  Fully reviewed
cases can additionally freeze their exact finding sites so precision
regressions fail the gate.  A case without either marker is still scanned and
reported; it is not assumed to be safe.  Every input is copied to a temporary
directory so IDA never creates or updates databases next to the original
challenge files.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import tempfile
import time


PROJECT_ROOT = Path(__file__).resolve().parents[1]
QUICK_SCAN = Path(__file__).with_name("quick_scan.py")
DEFAULT_ROOT = Path("/Users/flower/ctf/ccb-final")
DEFAULT_IDA = Path("/Applications/IDA Professional 9.4.app/Contents/MacOS/idat")


@dataclass(frozen=True, slots=True)
class ExpectedHit:
    rule_id: str
    ea: int
    root: str


@dataclass(frozen=True, slots=True)
class CCBCase:
    name: str
    path: str
    expected: tuple[ExpectedHit, ...] = ()
    expect_no_findings: bool = False
    expect_exact_findings: bool = False


CASES = (
    CCBCase(
        "hash_archiver",
        "HashArchiver/pwn",
        (
            ExpectedHit(
                "BUF-011",
                0x4035C6,
                "persistent record counter outgrows a 288-byte stack result array during bucket traversal",
            ),
        ),
        expect_exact_findings=True,
    ),
    CCBCase(
        "credit_market",
        "CreditMarket/shop",
        (
            ExpectedHit(
                "BUF-010",
                0x19F1,
                "stored allocation size is enlarged by 64 during edit",
            ),
        ),
        expect_exact_findings=True,
    ),
    CCBCase(
        "hero_editor",
        "HeroEditor/game",
        (
            ExpectedHit(
                "BUF-007",
                0x14C8,
                "preview loop can read 48 bytes from a 24-byte draft stack object, disclosing the adjacent canary and return state",
            ),
            ExpectedHit(
                "BUF-004",
                0x204E,
                "bounded read wrapper writes up to 232 bytes into a 24-byte stack object",
            ),
        ),
        expect_exact_findings=True,
    ),
    CCBCase(
        "somewin",
        "somewin/pwn",
        (
            ExpectedHit(
                "LIFE-003",
                0xF7DB,
                "custom pool release leaves the indexed global object slot dangling",
            ),
            ExpectedHit(
                "LIFE-007",
                0xFE7F,
                "indirect callback is loaded from the retained freed object",
            ),
        ),
        expect_exact_findings=True,
    ),
    CCBCase("somebox", "somebox/pwn", expect_no_findings=True),
    CCBCase(
        "someploy",
        "someploy/someploys",
        (
            ExpectedHit(
                "IDX-003",
                0x1DCA,
                "signed 8-bit bounds checks authorize unsigned 8-bit indexes into 64-entry global tables",
            ),
        ),
        expect_exact_findings=True,
    ),
    CCBCase("chall", "chall/chall", expect_no_findings=True),
    CCBCase(
        "protokms",
        "protobuf/protokms",
        (
            ExpectedHit(
                "LIFE-003",
                0x2818,
                "CREATE failure frees a global slot pointer without clearing it",
            ),
        ),
        expect_exact_findings=True,
    ),
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--root",
        type=Path,
        default=Path(os.environ.get("PWN_HUNTER_CCB_ROOT", DEFAULT_ROOT)),
    )
    parser.add_argument(
        "--ida",
        type=Path,
        default=Path(os.environ.get("PWN_HUNTER_IDA", DEFAULT_IDA)),
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path(__file__).with_name("ccb-result.json"),
    )
    parser.add_argument("--case", action="append", dest="cases")
    parser.add_argument("--timeout", type=float, default=120.0)
    parser.add_argument("--max-functions", type=int, default=240)
    parser.add_argument("--max-seconds", type=float, default=25.0)
    return parser.parse_args()


def run_case(
    case: CCBCase, args: argparse.Namespace, workdir: Path
) -> dict[str, object]:
    started = time.monotonic()
    source = args.root / case.path
    case_dir = workdir / case.name
    case_dir.mkdir(parents=True)
    target = case_dir / "target"
    shutil.copy2(source, target)
    target.chmod(target.stat().st_mode | stat.S_IXUSR)

    result_path = workdir / f"{case.name}.json"
    log_path = workdir / f"{case.name}.log"
    environment = os.environ.copy()
    environment.update(
        {
            "PWN_HUNTER_RESULT": str(result_path),
            "PWN_HUNTER_MAX_FUNCTIONS": str(args.max_functions),
            "PWN_HUNTER_MAX_SECONDS": str(args.max_seconds),
        }
    )
    command = [
        str(args.ida),
        "-A",
        "-c",
        f"-L{log_path}",
        f"-S{QUICK_SCAN}",
        str(target),
    ]
    result: dict[str, object] = {
        "name": case.name,
        "path": case.path,
        "expected": [
            {"rule_id": hit.rule_id, "ea": hit.ea, "root": hit.root}
            for hit in case.expected
        ],
        "expect_no_findings": case.expect_no_findings,
        "expect_exact_findings": case.expect_exact_findings,
    }
    try:
        process = subprocess.run(
            command,
            env=environment,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=args.timeout,
            check=False,
        )
        result["returncode"] = process.returncode
        if result_path.is_file():
            result.update(json.loads(result_path.read_text(encoding="utf-8")))
        else:
            result["error"] = "IDA did not produce a result JSON"
        if process.returncode or "error" in result:
            result["process_output_tail"] = process.stdout[-4000:]
    except subprocess.TimeoutExpired as error:
        output = error.stdout or ""
        if isinstance(output, bytes):
            output = output.decode("utf-8", errors="replace")
        result.update(
            {
                "returncode": None,
                "error": f"IDA process exceeded {args.timeout:.1f}s timeout",
                "process_output_tail": output[-4000:],
            }
        )

    finding_sites = {
        (str(finding.get("rule_id")), int(finding.get("ea", -1)))
        for finding in result.get("findings", [])
        if isinstance(finding, dict)
    }
    missing = [
        {"rule_id": hit.rule_id, "ea": hit.ea, "root": hit.root}
        for hit in case.expected
        if (hit.rule_id, hit.ea) not in finding_sites
    ]
    result["missing_expected"] = missing
    result["matched_expected"] = len(case.expected) - len(missing)
    expected_sites = {(hit.rule_id, hit.ea) for hit in case.expected}
    result["unexpected_findings"] = (
        [
            {
                "rule_id": finding.get("rule_id"),
                "ea": finding.get("ea"),
                "summary": finding.get("summary"),
            }
            for finding in result.get("findings", [])
            if isinstance(finding, dict)
            and (
                case.expect_no_findings
                or (
                    str(finding.get("rule_id")), int(finding.get("ea", -1))
                )
                not in expected_sites
            )
        ]
        if case.expect_no_findings or case.expect_exact_findings
        else []
    )
    result["wall_seconds"] = round(time.monotonic() - started, 3)
    return result


def main() -> int:
    args = parse_args()
    if not args.ida.is_file():
        raise SystemExit(f"IDA executable not found: {args.ida}")
    selected = [case for case in CASES if not args.cases or case.name in args.cases]
    unknown = set(args.cases or ()) - {case.name for case in CASES}
    if unknown:
        raise SystemExit(f"unknown case(s): {', '.join(sorted(unknown))}")
    missing_inputs = [case.path for case in selected if not (args.root / case.path).is_file()]
    if missing_inputs:
        raise SystemExit("missing corpus input(s): " + ", ".join(missing_inputs))

    results: list[dict[str, object]] = []
    with tempfile.TemporaryDirectory(prefix="pwnhunter-ccb-") as temporary:
        workdir = Path(temporary)
        for index, case in enumerate(selected, 1):
            print(f"[{index}/{len(selected)}] {case.name}", flush=True)
            result = run_case(case, args, workdir)
            results.append(result)
            print(
                f"  return={result.get('returncode')} "
                f"scanned={result.get('stats', {}).get('scanned_functions', 0)} "
                f"findings={len(result.get('findings', []))} "
                f"expected={result.get('matched_expected', 0)}/"
                f"{len(result.get('expected', []))} "
                f"wall={result['wall_seconds']}s",
                flush=True,
            )

    failed = [item["name"] for item in results if item.get("returncode") != 0]
    missing_expected = [
        {"case": item["name"], **missing}
        for item in results
        for missing in item.get("missing_expected", [])
    ]
    unexpected_findings = [
        {"case": item["name"], **finding}
        for item in results
        for finding in item.get("unexpected_findings", [])
    ]
    unexpected_negative_findings = [
        finding
        for finding in unexpected_findings
        if next(
            item for item in results if item["name"] == finding["case"]
        ).get("expect_no_findings")
    ]
    unexpected_exact_findings = [
        finding
        for finding in unexpected_findings
        if next(
            item for item in results if item["name"] == finding["case"]
        ).get("expect_exact_findings")
    ]
    failed_cases = sorted(
        set(failed)
        | {item["case"] for item in missing_expected}
        | {item["case"] for item in unexpected_findings}
    )
    report = {
        "configuration": {
            "root": str(args.root),
            "ida": str(args.ida),
            "max_functions": args.max_functions,
            "max_seconds": args.max_seconds,
            "process_timeout": args.timeout,
        },
        "totals": {
            "cases": len(results),
            "passed": len(results) - len(failed_cases),
            "failed": failed_cases,
            "process_failed": failed,
            "findings": sum(len(item.get("findings", [])) for item in results),
            "expected": sum(len(item.get("expected", [])) for item in results),
            "matched_expected": sum(
                int(item.get("matched_expected", 0)) for item in results
            ),
            "missing_expected": missing_expected,
            "negative_cases": sum(
                bool(item.get("expect_no_findings")) for item in results
            ),
            "clean_negative_cases": sum(
                bool(item.get("expect_no_findings"))
                and not item.get("unexpected_findings")
                for item in results
            ),
            "unexpected_negative_findings": unexpected_negative_findings,
            "exact_cases": sum(
                bool(item.get("expect_exact_findings")) for item in results
            ),
            "clean_exact_cases": sum(
                bool(item.get("expect_exact_findings"))
                and not item.get("unexpected_findings")
                for item in results
            ),
            "unexpected_exact_findings": unexpected_exact_findings,
            "unexpected_findings": unexpected_findings,
            "wall_seconds": round(
                sum(float(item["wall_seconds"]) for item in results), 3
            ),
        },
        "results": results,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(f"report: {args.output}")
    return 1 if failed or missing_expected or unexpected_findings else 0


if __name__ == "__main__":
    raise SystemExit(main())
