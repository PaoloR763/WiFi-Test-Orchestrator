from __future__ import annotations

import shutil
import subprocess
import sys
import tempfile
import venv
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PROJECT = ROOT / "agents" / "desktop"


def run(*command: str, cwd: Path | None = None) -> None:
    subprocess.run(command, cwd=cwd or ROOT, check=True)  # noqa: S603


def main() -> None:
    run(sys.executable, str(ROOT / "scripts" / "sync_desktop_contracts.py"), "--check")
    with tempfile.TemporaryDirectory(prefix="wto-wheel-") as temporary:
        temp = Path(temporary)
        wheelhouse = temp / "wheelhouse"
        wheelhouse.mkdir()
        cached_wheelhouse = Path("/opt/wto-wheelhouse")
        cached_wheels = tuple(cached_wheelhouse.glob("*.whl"))
        if cached_wheels:
            for cached in cached_wheels:
                shutil.copy2(cached, wheelhouse / cached.name)
        else:
            run(
                sys.executable,
                "-m",
                "pip",
                "wheel",
                "--requirement",
                str(PROJECT / "requirements.lock"),
                "--wheel-dir",
                str(wheelhouse),
                cwd=temp,
            )
        run(
            sys.executable,
            "-m",
            "pip",
            "wheel",
            str(PROJECT),
            "--wheel-dir",
            str(wheelhouse),
            "--no-build-isolation",
            "--no-deps",
            cwd=temp,
        )
        environment = temp / "venv"
        venv.EnvBuilder(with_pip=True, clear=True).create(environment)
        python = environment / (
            "Scripts/python.exe" if sys.platform == "win32" else "bin/python"
        )
        run(
            str(python),
            "-m",
            "pip",
            "install",
            "--no-index",
            "--find-links",
            str(wheelhouse),
            "wto-desktop-agent==0.1.0",
        )
        run(str(python), "-m", "pip", "check")
        validation = r"""
import json
from pathlib import Path
from wto_desktop_agent.infrastructure.contracts import (
    ContractValidationError,
    contract_root,
    schema_store,
    validate_contract,
)
root = contract_root()
schemas, _ = schema_store()
manifest = json.loads((root / "examples" / "manifest.json").read_text(encoding="utf-8"))
catalog = json.loads((root / "catalog" / "capabilities-1.0.0.json").read_text(encoding="utf-8"))
assert len(schemas) == 14
assert len(manifest["fixtures"]) == 25
assert len(catalog["capability_ids"]) == 15
from wto_desktop_agent.platforms.windows.powershell import verify_inventory_script
packaged_inventory_script = verify_inventory_script()
source_inventory_script = (
    Path.cwd()
    / "agents"
    / "desktop"
    / "src"
    / "wto_desktop_agent"
    / "platforms"
    / "windows"
    / "scripts"
    / "network_inventory.ps1"
)
assert packaged_inventory_script.is_file()
assert packaged_inventory_script.read_bytes() == source_inventory_script.read_bytes()
for entry in manifest["fixtures"]:
    payload = json.loads((root / "examples" / entry["path"]).read_text(encoding="utf-8"))
    try:
        validate_contract(entry["schema"], payload)
        accepted = True
    except ContractValidationError:
        accepted = False
    assert accepted is bool(entry["valid"]), entry["path"]
print(json.dumps({
    "schemas": 14,
    "fixtures": 25,
    "capabilities": 15,
    "wheel": "installed",
    "inventory_script": "verified",
}))
"""
        run(str(python), "-c", validation)


if __name__ == "__main__":
    main()
