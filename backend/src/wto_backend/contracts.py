from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker
from referencing import Registry, Resource

CONTRACT_VERSION = "1.0.0"
AGENT_PROTOCOL_VERSION = "1.0.0"


class ContractValidationError(ValueError):
    def __init__(self, errors: list[dict[str, object]]) -> None:
        super().__init__("contract validation failed")
        self.errors = errors


def contract_root() -> Path:
    packaged = Path(__file__).with_name("contract_data")
    if packaged.exists():
        return packaged
    return Path(__file__).resolve().parents[3] / "shared" / "contracts"


@lru_cache
def schema_store() -> tuple[dict[str, dict[str, Any]], Registry[Any]]:
    schemas: dict[str, dict[str, Any]] = {}
    registry: Registry[Any] = Registry()
    for path in sorted((contract_root() / "schemas").glob("*.schema.json")):
        document = json.loads(path.read_text(encoding="utf-8"))
        schemas[path.name] = document
        resource = Resource.from_contents(document)
        registry = registry.with_resource(document["$id"], resource)
        registry = registry.with_resource(path.as_uri(), resource)
    return schemas, registry


def validate_contract(schema_name: str, payload: object) -> None:
    ensure_json_depth(payload)
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


def ensure_json_depth(payload: object, *, maximum: int = 16) -> None:
    def visit(value: object, depth: int) -> None:
        if depth > maximum:
            raise ContractValidationError([{"location": [], "type": "maxDepth"}])
        if isinstance(value, dict):
            if len(value) > 128:
                raise ContractValidationError([{"location": [], "type": "maxProperties"}])
            for item in value.values():
                visit(item, depth + 1)
        elif isinstance(value, list):
            if len(value) > 128:
                raise ContractValidationError([{"location": [], "type": "maxItems"}])
            for item in value:
                visit(item, depth + 1)

    visit(payload, 1)


def canonical_json(payload: object) -> bytes:
    """Canonical validated JSON used for fingerprints.

    This profile forbids NaN/Infinity, sorts object keys, emits UTF-8 without
    insignificant whitespace and retains array order. Contract numbers used by
    idempotent operations are integers, avoiding cross-runtime float ambiguity.
    """

    return json.dumps(
        payload,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
