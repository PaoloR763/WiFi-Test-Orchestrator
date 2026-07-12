from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend" / "src"))

from wto_backend.contracts import (  # noqa: E402
    ContractValidationError,
    validate_contract,
)


def main() -> None:
    examples = ROOT / "shared" / "contracts" / "examples"
    manifest = json.loads((examples / "manifest.json").read_text(encoding="utf-8"))
    failures: list[str] = []
    for entry in manifest["fixtures"]:
        payload = json.loads((examples / entry["path"]).read_text(encoding="utf-8"))
        try:
            validate_contract(entry["schema"], payload)
            actual_valid = True
            validators: set[str] = set()
        except ContractValidationError as error:
            actual_valid = False
            validators = {str(item["type"]) for item in error.errors}
        if actual_valid != entry["valid"]:
            failures.append(f"{entry['path']}: expected valid={entry['valid']}")
        expected_error = entry["error"]
        if not actual_valid and expected_error not in validators:
            failures.append(
                f"{entry['path']}: expected validator {expected_error}, got {sorted(validators)}"
            )
    if failures:
        for failure in failures:
            print(failure, file=sys.stderr)
        raise SystemExit(1)
    print(f"Validated {len(manifest['fixtures'])} normative contract fixtures.")


if __name__ == "__main__":
    main()
