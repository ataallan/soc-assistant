#!/usr/bin/env python3
"""Create a rotated SQLite backup of the SOC Assistant database."""

from __future__ import annotations

import argparse
import sys

from db import BACKUP_KEEP_DEFAULT, backup_sqlite


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Back up the SQLite SOC database.")
    parser.add_argument(
        "--dest-dir",
        default="data/backups",
        help="Directory for backup files (default: data/backups)",
    )
    parser.add_argument(
        "--keep",
        type=int,
        default=BACKUP_KEEP_DEFAULT,
        help=f"Number of recent backups to keep (default: {BACKUP_KEEP_DEFAULT})",
    )
    args = parser.parse_args(argv)

    result = backup_sqlite(dest_dir=args.dest_dir, keep=args.keep)
    print(result.get("message") or ("OK" if result.get("ok") else "Backup failed."))
    if result.get("path"):
        print(f"path={result['path']}")
    return 0 if result.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())
