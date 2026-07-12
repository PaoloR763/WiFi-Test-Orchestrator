from __future__ import annotations

import argparse
import json
import shutil
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
CONTRACTS = ROOT / "shared" / "contracts"
CANONICAL = CONTRACTS / "openapi" / "openapi.json"
PACKAGE = ROOT / "backend" / "src" / "wto_backend" / "contract_data"
BUNDLED = PACKAGE / "openapi-bundled.json"


def schema_key(path: Path) -> str:
    document = json.loads(path.read_text(encoding="utf-8"))
    title = str(document["title"])
    return "".join(character for character in title if character.isalnum())


def bundle(document: dict[str, Any]) -> dict[str, Any]:
    schema_paths = sorted((CONTRACTS / "schemas").glob("*.schema.json"))
    mapping = {path.name: schema_key(path) for path in schema_paths}

    def replace(value: Any, *, current_schema: str | None) -> Any:
        if isinstance(value, dict):
            result = {
                key: replace(item, current_schema=current_schema) for key, item in value.items()
            }
            reference = result.get("$ref")
            if isinstance(reference, str) and ".schema.json" in reference:
                path_part, separator, fragment = reference.partition("#")
                name = Path(path_part).name
                if name in mapping:
                    result["$ref"] = f"#/components/schemas/{mapping[name]}"
                    if separator:
                        result["$ref"] += f"/{fragment.lstrip('/')}"
            elif (
                isinstance(reference, str)
                and current_schema is not None
                and reference.startswith("#/")
            ):
                result["$ref"] = (
                    f"#/components/schemas/{current_schema}/{reference.removeprefix('#/')}"
                )
            return result
        if isinstance(value, list):
            return [replace(item, current_schema=current_schema) for item in value]
        return value

    bundled = replace(document, current_schema=None)
    schemas = {
        mapping[path.name]: replace(
            json.loads(path.read_text(encoding="utf-8")),
            current_schema=mapping[path.name],
        )
        for path in schema_paths
    }
    bundled.setdefault("components", {}).setdefault("schemas", {}).update(schemas)
    return bundled


def rendered_bundle() -> str:
    canonical = json.loads(CANONICAL.read_text(encoding="utf-8"))
    return json.dumps(bundle(canonical), ensure_ascii=False, indent=2, sort_keys=True) + "\n"


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    rendered = rendered_bundle()
    if args.check:
        if not BUNDLED.exists() or BUNDLED.read_text(encoding="utf-8") != rendered:
            raise SystemExit("bundled OpenAPI drift detected; run scripts/build_openapi.py")
        print("Bundled OpenAPI matches the canonical contract.")
        return
    PACKAGE.mkdir(parents=True, exist_ok=True)
    for directory in ("schemas", "examples", "catalog"):
        if (PACKAGE / directory).exists():
            shutil.rmtree(PACKAGE / directory)
        shutil.copytree(CONTRACTS / directory, PACKAGE / directory)
    BUNDLED.write_text(rendered, encoding="utf-8", newline="\n")
    print("Generated backend contract data and bundled OpenAPI.")


if __name__ == "__main__":
    main()
