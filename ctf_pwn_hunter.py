"""IDA plugin entry point for PwnHunter."""

from __future__ import annotations

import ida_hexrays
import ida_idaapi
import ida_idp
import ida_kernwin
import ida_loader

from pwnhunter.ida_adapter import IDAScanner


ACTION_CURRENT = "pwnhunter:scan_current"
ACTION_DEEP = "pwnhunter:scan_deep"
ACTION_CLEAR_CACHE = "pwnhunter:clear_cache"
PLUGIN_MENU_PATH = "Edit/Plugins/PwnHunter: Quick scan"


def ensure_hexrays() -> bool:
    if ida_hexrays.init_hexrays_plugin():
        return True
    decompilers = {
        ida_idp.PLFM_386: "hexx64",
        ida_idp.PLFM_ARM: "hexarm",
        ida_idp.PLFM_PPC: "hexppc",
        ida_idp.PLFM_MIPS: "hexmips",
        ida_idp.PLFM_RISCV: "hexrv",
    }
    plugin_name = decompilers.get(ida_idp.ph.id)
    return bool(
        plugin_name
        and ida_loader.load_plugin(plugin_name)
        and ida_hexrays.init_hexrays_plugin()
    )


class ScanCurrentHandler(ida_kernwin.action_handler_t):
    def __init__(self, scanner: IDAScanner):
        super().__init__()
        self.scanner = scanner

    def activate(self, _context):
        self.scanner.scan_current_function()
        return 1

    def update(self, context):
        if context.widget_type in {
            ida_kernwin.BWN_PSEUDOCODE,
            ida_kernwin.BWN_DISASM,
        }:
            return ida_kernwin.AST_ENABLE_FOR_WIDGET
        return ida_kernwin.AST_DISABLE_FOR_WIDGET


class ScanDeepHandler(ida_kernwin.action_handler_t):
    def __init__(self, scanner: IDAScanner):
        super().__init__()
        self.scanner = scanner

    def activate(self, _context):
        self.scanner.scan_deep()
        return 1

    def update(self, _context):
        return ida_kernwin.AST_ENABLE_ALWAYS


class ClearCacheHandler(ida_kernwin.action_handler_t):
    def __init__(self, scanner: IDAScanner):
        super().__init__()
        self.scanner = scanner

    def activate(self, _context):
        self.scanner.clear_cache()
        print("[PwnHunter] Analysis cache cleared.")
        return 1

    def update(self, _context):
        return ida_kernwin.AST_ENABLE_ALWAYS


class PopupHooks(ida_hexrays.Hexrays_Hooks):
    def populating_popup(self, _widget, _popup, vu):
        ida_kernwin.attach_action_to_popup(vu.ct, None, ACTION_CURRENT)
        return 0


class PwnHunterPlugin(ida_idaapi.plugin_t):
    flags = ida_idaapi.PLUGIN_PROC
    comment = "Fast deterministic vulnerability-candidate scanner for CTF pwn"
    help = "Scan the binary for common pwn vulnerability candidates"
    wanted_name = "PwnHunter: Quick scan"
    wanted_hotkey = "Ctrl+Shift+H"

    def init(self):
        if not ensure_hexrays():
            print("[PwnHunter] Hex-Rays decompiler is required.")
            return ida_idaapi.PLUGIN_SKIP

        self.scanner = IDAScanner()
        self.current_handler = ScanCurrentHandler(self.scanner)
        self.deep_handler = ScanDeepHandler(self.scanner)
        self.clear_cache_handler = ClearCacheHandler(self.scanner)
        actions = (
            (
                ACTION_CURRENT,
                "PwnHunter: Scan current function",
                self.current_handler,
                "Ctrl+Alt+H",
                "Scan the current function for pwn vulnerability candidates",
            ),
            (
                ACTION_DEEP,
                "PwnHunter: Deep scan",
                self.deep_handler,
                "Ctrl+Shift+Alt+H",
                "Scan a larger bounded set of non-library functions",
            ),
            (
                ACTION_CLEAR_CACHE,
                "PwnHunter: Clear analysis cache",
                self.clear_cache_handler,
                "",
                "Clear extracted function IR after changing types or prototypes",
            ),
        )
        for action_name, label, handler, hotkey, tooltip in actions:
            ida_kernwin.unregister_action(action_name)
            registered = ida_kernwin.register_action(
                ida_kernwin.action_desc_t(
                    action_name,
                    label,
                    handler,
                    hotkey,
                    tooltip,
                )
            )
            if not registered and ida_kernwin.is_idaq():
                print(f"[PwnHunter] Failed to register action {action_name}.")
        if ida_kernwin.is_idaq():
            for action_name in (ACTION_DEEP, ACTION_CLEAR_CACHE):
                ida_kernwin.attach_action_to_menu(
                    PLUGIN_MENU_PATH, action_name, ida_kernwin.SETMENU_APP
                )
        self.popup_hooks = PopupHooks()
        self.popup_hooks.hook()
        print(
            "[PwnHunter] Loaded. Ctrl+Shift+H quick-scans the binary; "
            "Ctrl+Alt+H scans the current function; Ctrl+Shift+Alt+H deep-scans."
        )
        return ida_idaapi.PLUGIN_KEEP

    def run(self, _argument):
        self.scanner.scan_all()

    def term(self):
        if hasattr(self, "popup_hooks"):
            self.popup_hooks.unhook()
        if ida_kernwin.is_idaq():
            for action_name in (ACTION_DEEP, ACTION_CLEAR_CACHE):
                ida_kernwin.detach_action_from_menu(PLUGIN_MENU_PATH, action_name)
        for action_name in (ACTION_CURRENT, ACTION_DEEP, ACTION_CLEAR_CACHE):
            ida_kernwin.unregister_action(action_name)


def PLUGIN_ENTRY():
    return PwnHunterPlugin()
