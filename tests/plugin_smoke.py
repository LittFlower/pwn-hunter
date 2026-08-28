"""Verify that IDA discovers and initializes the installed plugin."""

import os
from pathlib import Path

import ida_auto
import ida_kernwin
import ida_loader
import ida_pro

from pwnhunter import __version__


ida_auto.auto_wait()
loaded = ida_loader.find_plugin("ctf_pwn_hunter", True) is not None
actions = ida_kernwin.get_registered_actions()
matching_actions = [name for name in actions if "pwnhunter" in name.lower()]
expected_actions = {
    "pwnhunter:scan_current",
    "pwnhunter:scan_deep",
    "pwnhunter:clear_cache",
}
headless = not ida_kernwin.is_idaq()
actions_ok = headless or all(
    ida_kernwin.get_action_label(name) for name in expected_actions
)
action_status = [
    f"{name}={ida_kernwin.get_action_label(name)!r}"
    for name in sorted(expected_actions)
]
result = Path(os.environ.get("PWN_HUNTER_SMOKE", "/tmp/pwnhunter-smoke.txt"))
result.write_text(
    ("loaded\n" if loaded else "missing\n")
    + f"version={__version__}\n"
    + (
        "actions-skipped-headless\n"
        if headless
        else ("actions-ok\n" if actions_ok else "actions-missing\n")
    )
    + "\n".join(action_status + matching_actions),
    encoding="utf-8",
)
ida_pro.qexit(0 if loaded and actions_ok else 1)
