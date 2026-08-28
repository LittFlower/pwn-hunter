"""Run PwnHunter's budgeted scan over the bundled AWDP challenge corpus.

The archive manifest is intentionally explicit: extracting only the service
binary keeps the benchmark fast and avoids unpacking multi-gigabyte challenge
images or bundled libc/sysroot files.  Explicit security-relevant sidecars are
materialized only for cases whose service loads code from those files.
"""

from __future__ import annotations

import argparse
from collections import Counter
from dataclasses import dataclass
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import tempfile
import time
import zipfile


PROJECT_ROOT = Path(__file__).resolve().parents[1]
CORPUS_ROOT = PROJECT_ROOT / "test_problem"
QUICK_SCAN = Path(__file__).with_name("quick_scan.py")
DEFAULT_IDA = Path("/Applications/IDA Professional 9.4.app/Contents/MacOS/idat")


@dataclass(frozen=True, slots=True)
class CorpusCase:
    name: str
    archive: str | None = None
    member: str | None = None
    path: str | None = None
    companions: tuple[str, ...] = ()


CASES = (
    CorpusCase(
        "chr",
        "AWDP-PWN-CHR.zip",
        "AWDP-PWN-CHR/pwn",
        companions=("AWDP-PWN-CHR/ISO-2022-CN-EXT.so",),
    ),
    CorpusCase("anime", "AWDP-PWN-anime.zip", "AWDP-PWN-anime/pwn"),
    CorpusCase("ezheap", "AWDP-PWN-ezheap.zip", "AWDP-PWN-ezheap/pwn"),
    CorpusCase(
        "embedded_httpd",
        "awdp-pwn-embbed_httpd_deab0f623aacb7a84ae4222613136c6e.zip",
        "bin/pwn",
    ),
    CorpusCase("broken_manager", "broken_manager.zip", "pwn"),
    CorpusCase("catchme", "catchme.zip", "catchme"),
    CorpusCase("easy_rw", "easy_rw_revenge.zip", "pwn"),
    CorpusCase("easy_rw_proxy", "easy_rw_revenge.zip", "proxy"),
    CorpusCase("minidb", "minidb.zip", "pwn"),
    CorpusCase("darkheap", path="darkheap/DarkHeap"),
    CorpusCase("loginsystem", path="loginsystem/LoginSystem"),
)

SKIPPED = (
    {
        "name": "php",
        "archive": "AWDP-PWN-PHP.zip",
        "reason": (
            "archive contains only container tarballs (about 1.8 GB compressed) "
            "and no standalone service executable"
        ),
    },
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--ida",
        type=Path,
        default=Path(os.environ.get("PWN_HUNTER_IDA", DEFAULT_IDA)),
        help="path to the headless IDA executable",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path(__file__).with_name("corpus-result.json"),
    )
    parser.add_argument("--case", action="append", dest="cases")
    parser.add_argument("--timeout", type=float, default=120.0)
    parser.add_argument("--max-functions", type=int, default=180)
    parser.add_argument("--max-seconds", type=float, default=15.0)
    parser.add_argument("--keep-workdir", action="store_true")
    return parser.parse_args()


def materialize(case: CorpusCase, workdir: Path) -> tuple[Path, dict[str, object]]:
    case_dir = workdir / case.name
    case_dir.mkdir(parents=True)
    if case.path:
        source = CORPUS_ROOT / case.path
        target = case_dir / source.name
        shutil.copy2(source, target)
        metadata = {"path": case.path}
    else:
        if not case.archive or not case.member:
            raise ValueError(f"incomplete corpus case: {case.name}")
        archive = CORPUS_ROOT / case.archive
        target = case_dir / Path(case.member).name
        with zipfile.ZipFile(archive) as package:
            with package.open(case.member) as source, target.open("wb") as output:
                shutil.copyfileobj(source, output)
            for companion in case.companions:
                companion_target = case_dir / Path(companion).name
                with (
                    package.open(companion) as source,
                    companion_target.open("wb") as output,
                ):
                    shutil.copyfileobj(source, output)
        metadata = {"archive": case.archive, "member": case.member}
        if case.companions:
            metadata["companions"] = list(case.companions)
    target.chmod(target.stat().st_mode | stat.S_IXUSR)
    return target, metadata


def run_case(
    case: CorpusCase, args: argparse.Namespace, workdir: Path
) -> dict[str, object]:
    started = time.monotonic()
    target, metadata = materialize(case, workdir)
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
    result: dict[str, object] = {"name": case.name, **metadata}
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
        if result_path.exists():
            payload = json.loads(result_path.read_text(encoding="utf-8"))
            findings = payload.get("findings", [])
            result.update(payload)
            result["finding_group_counts"] = dict(
                sorted(Counter(item["rule_id"] for item in findings).items())
            )
            result["finding_counts"] = dict(
                sorted(
                    Counter(
                        {
                            rule_id: sum(
                                int(item.get("occurrences", 1))
                                for item in findings
                                if item["rule_id"] == rule_id
                            )
                            for rule_id in {item["rule_id"] for item in findings}
                        }
                    ).items()
                )
            )
            result["severity_group_counts"] = dict(
                sorted(Counter(item["severity"] for item in findings).items())
            )
            result["severity_counts"] = dict(
                sorted(
                    {
                        severity: sum(
                            int(item.get("occurrences", 1))
                            for item in findings
                            if item["severity"] == severity
                        )
                        for severity in {item["severity"] for item in findings}
                    }.items()
                )
            )
        else:
            result["error"] = "IDA did not produce a result JSON"
        if process.returncode or "error" in result:
            result["process_output_tail"] = process.stdout[-4000:]
    except subprocess.TimeoutExpired as error:
        timeout_output = error.stdout or ""
        if isinstance(timeout_output, bytes):
            timeout_output = timeout_output.decode("utf-8", errors="replace")
        result.update(
            {
                "returncode": None,
                "error": f"IDA process exceeded {args.timeout:.1f}s timeout",
                "process_output_tail": timeout_output[-4000:],
            }
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
        raise SystemExit(f"unknown corpus case(s): {', '.join(sorted(unknown))}")

    if args.keep_workdir:
        workdir = Path(tempfile.mkdtemp(prefix="pwnhunter-corpus-"))
        cleanup = None
    else:
        cleanup = tempfile.TemporaryDirectory(prefix="pwnhunter-corpus-")
        workdir = Path(cleanup.name)

    results: list[dict[str, object]] = []
    try:
        for index, case in enumerate(selected, 1):
            print(f"[{index}/{len(selected)}] {case.name}", flush=True)
            result = run_case(case, args, workdir)
            results.append(result)
            stats = result.get("stats", {})
            finding_count = len(result.get("findings", []))
            print(
                f"  return={result.get('returncode')} "
                f"scanned={stats.get('scanned_functions', 0)} "
                f"findings={finding_count} wall={result['wall_seconds']}s",
                flush=True,
            )

        failed = [item["name"] for item in results if item.get("returncode") != 0]
        totals = {
            "cases": len(results),
            "passed": len(results) - len(failed),
            "failed": failed,
            "findings": sum(len(item.get("findings", [])) for item in results),
            "finding_sites": sum(
                int(item.get("stats", {}).get("finding_sites", 0))
                for item in results
            ),
            "scanned_functions": sum(
                int(item.get("stats", {}).get("scanned_functions", 0))
                for item in results
            ),
            "wall_seconds": round(
                sum(float(item["wall_seconds"]) for item in results), 3
            ),
        }
        report = {
            "configuration": {
                "ida": str(args.ida),
                "max_functions": args.max_functions,
                "max_seconds": args.max_seconds,
                "process_timeout": args.timeout,
            },
            "totals": totals,
            "skipped": list(SKIPPED) if not args.cases else [],
            "results": results,
        }
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, indent=2), encoding="utf-8")
        print(f"report: {args.output}")
        if args.keep_workdir:
            print(f"workdir: {workdir}")
        return 1 if failed else 0
    finally:
        if cleanup is not None:
            cleanup.cleanup()


if __name__ == "__main__":
    raise SystemExit(main())
