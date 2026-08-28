"""Headless driver for budgeted quick or deep interprocedural scans."""

from __future__ import annotations

from dataclasses import asdict
import json
import os
import sys
import traceback
from pathlib import Path

import ida_auto
import ida_hexrays
import ida_pro


PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from pwnhunter.ida_adapter import IDAScanner  # noqa: E402


def main() -> int:
    output = Path(os.environ.get("PWN_HUNTER_RESULT", "/tmp/pwnhunter-quick.json"))
    ida_auto.auto_wait()
    if not ida_hexrays.init_hexrays_plugin():
        raise RuntimeError("Hex-Rays is unavailable")

    scanner = IDAScanner()
    scan_mode = os.environ.get("PWN_HUNTER_SCAN_MODE", "quick").strip().lower()
    if scan_mode not in {"quick", "deep"}:
        raise ValueError(f"unsupported PWN_HUNTER_SCAN_MODE: {scan_mode!r}")
    scan = scanner.scan_deep if scan_mode == "deep" else scanner.scan_quick
    findings = scan(show_ui=False)
    first_stats = asdict(scanner.last_stats)
    repeat_stats = None
    if os.environ.get("PWN_HUNTER_REPEAT"):
        scan(show_ui=False)
        repeat_stats = asdict(scanner.last_stats)
    payload = {
        "scan_mode": scan_mode,
        "stats": first_stats,
        "candidates": [
            {
                "ea": candidate.ea,
                "score": candidate.score,
                "reasons": sorted(candidate.reasons),
            }
            for candidate in scanner.last_candidates
        ],
        "findings": [
            {
                "rule_id": finding.rule_id,
                "function": finding.function_name,
                "callee": finding.callee,
                "ea": finding.ea,
                "severity": finding.severity.label,
                "confidence": finding.confidence,
                "summary": finding.summary,
                "evidence": finding.evidence,
                "occurrences": finding.occurrences,
                "related_eas": list(finding.related_eas),
            }
            for finding in findings
        ],
    }
    if repeat_stats is not None:
        payload["repeat_stats"] = repeat_stats
    if os.environ.get("PWN_HUNTER_DEBUG_IR"):
        payload["debug_ir"] = {
            f"0x{ea:X}": repr(function)
            for ea, function in scanner._ir_cache.items()
        }
        payload["debug_summaries"] = {
            f"0x{ea:X}": repr(summary)
            for ea, summary in scanner.last_summaries.by_ea.items()
        }
    output.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return 0 if not scanner.last_stats.failures else 2


try:
    exit_code = main()
except Exception:
    traceback.print_exc()
    exit_code = 1
ida_pro.qexit(exit_code)
