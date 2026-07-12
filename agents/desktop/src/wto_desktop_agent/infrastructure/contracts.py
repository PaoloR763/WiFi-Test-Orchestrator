from __future__ import annotations

import json
from functools import lru_cache
from importlib.resources import files
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker
from referencing import Registry, Resource


class ContractValidationError(ValueError):
    def __init__(self, errors: list[dict[str, object]]) -> None:
        super().__init__("contract validation failed")
        self.errors = errors


def contract_root() -> Path:
    return Path(str(files("wto_desktop_agent").joinpath("contract_data")))


@lru_cache
def schema_store() -> tuple[dict[str, dict[str, Any]], Registry[Any]]:
    schemas: dict[str, dict[str, Any]] = {}
    registry: Registry[Any] = Registry()
    for path in sorted((contract_root() / "schemas").glob("*.schema.json")):
        document = json.loads(path.read_text(encoding="utf-8"))
        schemas[path.name] = document
        resource = Resource.from_contents(document)
        registry = registry.with_resource(str(document["$id"]), resource)
        registry = registry.with_resource(path.as_uri(), resource)
    if len(schemas) != 14:
        raise RuntimeError("desktop agent contract package must contain exactly 14 schemas")
    return schemas, registry


def validate_contract(schema_name: str, payload: object) -> None:
    schemas, registry = schema_store()
    try:
        schema = schemas[schema_name]
    except KeyError as error:
        raise ValueError(f"unknown contract schema: {schema_name}") from error
    validator = Draft202012Validator(schema, registry=registry, format_checker=FormatChecker())
    errors = sorted(validator.iter_errors(payload), key=lambda item: list(item.absolute_path))
    if errors:
        raise ContractValidationError(
            [
                {
                    "location": [str(item) for item in error.absolute_path],
                    "type": error.validator or "schema",
                }
                for error in errors[:32]
            ]
        )


def canonical_json(payload: object) -> bytes:
    return json.dumps(
        payload,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
