#!/usr/bin/env python3
"""System-level backup: copy bank.db into backups/ with timestamp + SHA-256 checksum."""

from __future__ import annotations

import hashlib
import shutil
from datetime import datetime, timezone
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "bank.db"
BACKUP_DIR = BASE_DIR / "backups"


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def main() -> None:
    if not DB_PATH.exists():
        print("ERROR: bank.db not found. Start the app once to create it.")
        raise SystemExit(1)

    BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    dest = BACKUP_DIR / f"bank_{stamp}.db"
    shutil.copy2(DB_PATH, dest)
    checksum = sha256_file(dest)
    checksum_file = BACKUP_DIR / f"bank_{stamp}.sha256"
    checksum_file.write_text(f"{checksum}  {dest.name}\n", encoding="utf-8")

    print(f"Backup created: {dest}")
    print(f"SHA-256:        {checksum}")
    print(f"Checksum file:  {checksum_file}")


if __name__ == "__main__":
    main()
