"""Install PwnHunter into an IDA user plugin directory."""

from __future__ import annotations

import argparse
import os
import shutil
from pathlib import Path


ROOT = Path(__file__).resolve().parent


def default_plugin_dir() -> Path:
    ida_user = os.environ.get("IDAUSR")
    return Path(ida_user).expanduser() / "plugins" if ida_user else Path.home() / ".idapro" / "plugins"


def install_target(source: Path, destination: Path, link: bool, force: bool) -> None:
    if destination.is_symlink() and destination.resolve() == source.resolve():
        print(f"already installed: {destination}")
        return
    if destination.exists() or destination.is_symlink():
        if not force:
            raise FileExistsError(
                f"{destination} already exists; use --force to replace it"
            )
        if destination.is_dir() and not destination.is_symlink():
            shutil.rmtree(destination)
        else:
            destination.unlink()

    if link:
        destination.symlink_to(source, target_is_directory=source.is_dir())
    elif source.is_dir():
        shutil.copytree(
            source,
            destination,
            ignore=shutil.ignore_patterns("__pycache__", "*.pyc"),
        )
    else:
        shutil.copy2(source, destination)
    print(f"installed: {destination}")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--plugin-dir",
        type=Path,
        default=default_plugin_dir(),
        help="IDA plugin directory (default: %(default)s)",
    )
    parser.add_argument(
        "--copy",
        action="store_true",
        help="copy files instead of creating development symlinks",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="replace an existing PwnHunter installation",
    )
    args = parser.parse_args()

    plugin_dir = args.plugin_dir.expanduser().resolve()
    plugin_dir.mkdir(parents=True, exist_ok=True)
    install_target(
        ROOT / "ctf_pwn_hunter.py",
        plugin_dir / "ctf_pwn_hunter.py",
        not args.copy,
        args.force,
    )
    install_target(
        ROOT / "pwnhunter",
        plugin_dir / "pwnhunter",
        not args.copy,
        args.force,
    )


if __name__ == "__main__":
    main()
