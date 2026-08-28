"""Reproduce the semantic corpus score from frozen manual labels.

Exact addresses alone are insufficient: an unrelated warning at the right
instruction is not a vulnerability match.  This file keeps the small,
reviewed mapping from each ground-truth root to acceptable deterministic rule
classes, then computes root/group and concrete-site metrics.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path


ROOT_RULES = {
    "chr-iconv-module-overflow": {"CVT-001"},
    "chr-unterminated-conversion-copy": {"STR-001", "STR-002"},
    "anime-format-string": {"FMT-001"},
    "ezheap-new-source-overread": {"BUF-009"},
    "ezheap-dangling-slot": {"LIFE-003"},
    "ezheap-modify-overflow": {"BUF-009"},
    "httpd-query-path-unterminated": {"STR-001"},
    "httpd-content-length-overflow": {"BUF-008"},
    "broken-manager-custom-free-uaf": {"LIFE-005"},
    "broken-manager-retained-custom-free-slot": {"LIFE-003"},
    "catchme-dangling-slot": {"LIFE-003"},
    "easy-rw-failed-replacement-dangling-slot": {"LIFE-003"},
    "easy-rw-zero-size-underflow": {"INT-004"},
    "easy-rw-uninitialized-send-length": {"INIT-001"},
    "proxy-auth-unterminated-string": {"STR-001"},
    "minidb-refcount-bypass": {"LIFE-006"},
    "darkheap-dangling-slot": {"LIFE-003"},
    "loginsystem-unbounded-credential-copy": {"BUF-004"},
}


def percentage(value: float) -> str:
    return f"{value * 100:.2f}%"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--ground-truth",
        type=Path,
        default=Path(__file__).with_name("ground_truth.json"),
    )
    parser.add_argument(
        "--result",
        type=Path,
        default=Path(__file__).with_name("corpus-result.json"),
    )
    args = parser.parse_args()
    truth = json.loads(args.ground_truth.read_text(encoding="utf-8"))
    result = json.loads(args.result.read_text(encoding="utf-8"))
    outputs = {item["name"]: item for item in result["results"]}

    roots = [root for case in truth["cases"] for root in case["roots"]]
    unknown = {root["id"] for root in roots} - set(ROOT_RULES)
    if unknown:
        raise SystemExit(f"unreviewed roots in ground truth: {sorted(unknown)}")

    recalled_roots: set[str] = set()
    matched_groups = 0
    true_sites: set[tuple[str, int]] = set()
    plugin_sites = 0
    plugin_groups = 0

    roots_by_case = {
        case["name"]: [
            (
                root["id"],
                {int(value, 0) for value in root["sink_eas"]},
                ROOT_RULES[root["id"]],
            )
            for root in case["roots"]
        ]
        for case in truth["cases"]
    }
    for case_name, case in outputs.items():
        reviewed = roots_by_case.get(case_name, [])
        for finding in case.get("findings", []):
            plugin_groups += 1
            sites = {int(finding["ea"]), *map(int, finding.get("related_eas", []))}
            plugin_sites += len(sites)
            group_matched = False
            for root_id, expected_sites, accepted_rules in reviewed:
                overlap = sites & expected_sites
                if finding["rule_id"] in accepted_rules and overlap:
                    recalled_roots.add(root_id)
                    true_sites.update((case_name, ea) for ea in overlap)
                    group_matched = True
            matched_groups += int(group_matched)

    total_roots = len(roots)
    total_sites = sum(len(root["sink_eas"]) for root in roots)
    root_precision = matched_groups / plugin_groups if plugin_groups else 0.0
    root_recall = len(recalled_roots) / total_roots if total_roots else 0.0
    root_f1 = (
        2 * root_precision * root_recall / (root_precision + root_recall)
        if root_precision + root_recall
        else 0.0
    )
    site_precision = len(true_sites) / plugin_sites if plugin_sites else 0.0
    site_recall = len(true_sites) / total_sites if total_sites else 0.0
    site_f1 = (
        2 * site_precision * site_recall / (site_precision + site_recall)
        if site_precision + site_recall
        else 0.0
    )
    print(
        f"groups: matched={matched_groups} total={plugin_groups} "
        f"precision={percentage(root_precision)}"
    )
    print(
        f"roots: recalled={len(recalled_roots)} total={total_roots} "
        f"recall={percentage(root_recall)} f1={percentage(root_f1)}"
    )
    print(
        f"sites: matched={len(true_sites)} total_plugin={plugin_sites} "
        f"total_truth={total_sites} precision={percentage(site_precision)} "
        f"recall={percentage(site_recall)} f1={percentage(site_f1)}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
