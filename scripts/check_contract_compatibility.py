from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any

BREAKING_KEYS = {
    "type",
    "required",
    "enum",
    "const",
    "pattern",
    "minimum",
    "maximum",
    "minLength",
    "maxLength",
    "minItems",
    "maxItems",
    "additionalProperties",
}
ROOT = Path(__file__).resolve().parents[1]
CONTRACTS = ROOT / "shared" / "contracts"
RELEASE_INTEGRITY = CONTRACTS / "catalog" / "release-integrity-1.0.0.json"


def compare(previous: Any, current: Any, path: str, failures: list[str]) -> None:
    if isinstance(previous, dict) and isinstance(current, dict):
        for key in BREAKING_KEYS & previous.keys() & current.keys():
            if previous[key] != current[key]:
                failures.append(f"{path}/{key}: validation rule changed")
        for key in previous.keys() - current.keys():
            failures.append(f"{path}/{key}: field/schema member removed")
        for key in previous.keys() & current.keys():
            compare(previous[key], current[key], f"{path}/{key}", failures)
    elif isinstance(previous, list) and isinstance(current, list) and previous != current:
        failures.append(f"{path}: ordered contract list changed")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("previous", type=Path, nargs="?")
    parser.add_argument("current", type=Path, nargs="?")
    release_operation = parser.add_mutually_exclusive_group()
    release_operation.add_argument("--verify-release", action="store_true")
    release_operation.add_argument("--refresh-release", action="store_true")
    args = parser.parse_args()
    if args.verify_release or args.refresh_release:
        release = json.loads(RELEASE_INTEGRITY.read_text(encoding="utf-8"))
        mismatches = []
        for relative, expected in release["files"].items():
            path = CONTRACTS / relative
            actual = hashlib.sha256(path.read_bytes()).hexdigest() if path.exists() else None
            if actual != expected:
                mismatches.append(relative)
                if args.refresh_release and actual is not None:
                    release["files"][relative] = actual
        if args.refresh_release:
            missing = [relative for relative in mismatches if not (CONTRACTS / relative).exists()]
            if missing:
                raise SystemExit("Cannot refresh missing published files: " + ", ".join(missing))
            RELEASE_INTEGRITY.write_text(
                json.dumps(release, ensure_ascii=False, indent=2) + "\n",
                encoding="utf-8",
                newline="\n",
            )
            print(
                f"Refreshed published contract integrity for {len(mismatches)} of "
                f"{len(release['files'])} files."
            )
            return
        if mismatches:
            raise SystemExit("Published contract integrity mismatch: " + ", ".join(mismatches))
        print(f"Published contract release integrity verified for {len(release['files'])} files.")
        return
    if args.previous is None or args.current is None:
        parser.error("previous and current are required unless --verify-release is used")
    failures: list[str] = []
    compare(
        json.loads(args.previous.read_text(encoding="utf-8")),
        json.loads(args.current.read_text(encoding="utf-8")),
        "$",
        failures,
    )
    if failures:
        raise SystemExit("Breaking contract changes detected:\n" + "\n".join(failures))
    print("No breaking contract changes detected.")


if __name__ == "__main__":
    main()
