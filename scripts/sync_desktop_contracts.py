from __future__ import annotations

import argparse
import hashlib
import json
import shutil
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "shared" / "contracts"
TARGET = ROOT / "agents" / "desktop" / "src" / "wto_desktop_agent" / "contract_data"
DIRECTORIES = ("schemas", "catalog", "examples", "openapi")


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def expected_files() -> dict[str, str]:
    release = json.loads(
        (SOURCE / "catalog" / "release-integrity-1.0.0.json").read_text(
            encoding="utf-8"
        )
    )
    declared = {str(name): str(digest) for name, digest in release["files"].items()}
    for name, digest in declared.items():
        path = SOURCE / name
        if not path.is_file() or sha256(path) != digest:
            raise SystemExit(f"canonical release integrity mismatch: {name}")
    result: dict[str, str] = {}
    for directory in DIRECTORIES:
        for path in sorted((SOURCE / directory).rglob("*")):
            if path.is_file():
                result[path.relative_to(SOURCE).as_posix()] = sha256(path)
    return result


def check(files: dict[str, str]) -> None:
    actual = (
        {
            path.relative_to(TARGET).as_posix(): sha256(path)
            for path in TARGET.rglob("*")
            if path.is_file()
        }
        if TARGET.exists()
        else {}
    )
    if actual != files:
        missing = sorted(files.keys() - actual.keys())
        extra = sorted(actual.keys() - files.keys())
        changed = sorted(
            name for name in files.keys() & actual.keys() if files[name] != actual[name]
        )
        raise SystemExit(
            f"desktop contract drift: missing={missing}, extra={extra}, changed={changed}"
        )
    print("Desktop contract package matches shared/contracts.")


def sync(files: dict[str, str]) -> None:
    if TARGET.exists():
        shutil.rmtree(TARGET)
    for name in files:
        destination = TARGET / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(SOURCE / name, destination)
    check(files)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    files = expected_files()
    if args.check:
        check(files)
    else:
        sync(files)


if __name__ == "__main__":
    main()
