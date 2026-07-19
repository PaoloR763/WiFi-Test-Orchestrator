from __future__ import annotations

import hashlib
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCAN_ROOTS = [
    ROOT / "backend",
    ROOT / "frontend",
    ROOT / "agents",
    ROOT / "deployment",
    ROOT / "integrations",
    ROOT / "mobile",
    ROOT / "shared",
    ROOT / "scripts",
    ROOT / "tests",
]
ROOT_FILES = [ROOT / "compose.yaml", ROOT / "Makefile"]
TEXT_SUFFIXES = {
    ".conf",
    ".css",
    ".html",
    ".ini",
    ".js",
    ".json",
    ".md",
    ".mako",
    ".ps1",
    ".py",
    ".sh",
    ".toml",
    ".ts",
    ".tsx",
    ".yaml",
    ".yml",
}

FORBIDDEN_CAPABILITY_IDS = [
    "wifi.current_connection",
    "wifi.rssi",
    "network.icmp_ping",
    "network.tcp_probe",
    "traffic.iperf3.tcp",
    "capture.monitor_80211",
    "replay.pcap",
    "execution.background_continuous",
]
EXPECTED_CONTRACT_SCHEMAS = {
    "agent-credential.schema.json",
    "agent-registration-request.schema.json",
    "agent-registration-response.schema.json",
    "artifact-manifest.schema.json",
    "capability-manifest.schema.json",
    "common.schema.json",
    "desktop-heartbeat.schema.json",
    "error-envelope.schema.json",
    "metric.schema.json",
    "mobile-presence.schema.json",
    "progress-event.schema.json",
    "reason.schema.json",
    "task-envelope.schema.json",
    "test-result.schema.json",
}
GRADLE_WRAPPER_JAR = Path("shared/contracts/consumers/kotlin/gradle/wrapper/gradle-wrapper.jar")
GRADLE_WRAPPER_JAR_SHA256 = "7d3a4ac4de1c32b59bc6a4eb8ecb8e612ccd0cf1ae1e99f66902da64df296172"
GRADLE_DISTRIBUTION_SHA256 = "7197a12f450794931532469d4ff21a59ea2c1cd59a3ec3f89c035c3c420a6999"
WINDOWS_CI_INSTALL_COMMANDS = (
    "python -m pip install --requirement agents/desktop/requirements-dev.lock",
    "python -m pip install --no-deps --editable agents/desktop",
    "python -m pip check",
)
LF_PATHS = (
    Path("scripts/dev.sh"),
    Path(".github/workflows/ci.yml"),
    Path(".gitattributes"),
    Path("shared/contracts/consumers/kotlin/gradlew"),
)
LINUX_PAYLOAD_ROOTS = (
    Path("agents/desktop/packaging/linux"),
    Path("scripts/linux"),
)


@dataclass(frozen=True)
class LinuxPayloadGitRecord:
    relative_path: str
    text_attribute: str
    eol_attribute: str
    index_content: bytes
    worktree_content: bytes
    filtered_autocrlf_true: bytes
    filtered_autocrlf_false: bytes


def _git_output(arguments: list[str], *, input_data: bytes | None = None) -> bytes:
    git = shutil.which("git")
    if git is None:
        raise RuntimeError("Git executable not found")
    completed = (
        subprocess.run(  # noqa: S603 - Git path and arguments are repository-controlled
            [git, *arguments],
            cwd=ROOT,
            check=False,
            input=input_data,
            capture_output=True,
        )
    )
    if completed.returncode != 0:
        detail = completed.stderr.decode("utf-8", errors="replace").strip()
        raise RuntimeError(detail or f"Git command failed: {' '.join(arguments)}")
    return completed.stdout


def collect_linux_payload_git_records() -> tuple[LinuxPayloadGitRecord, ...]:
    roots = [root.as_posix() for root in LINUX_PAYLOAD_ROOTS]
    tracked_raw = _git_output(["ls-files", "-z", "--", *roots])
    paths = tuple(
        sorted(
            value.decode("utf-8", errors="strict")
            for value in tracked_raw.split(b"\x00")
            if value
        )
    )
    attribute_input = b"".join(
        path.encode("utf-8", errors="strict") + b"\x00" for path in paths
    )
    attribute_raw = _git_output(
        ["check-attr", "--stdin", "-z", "text", "eol"],
        input_data=attribute_input,
    )
    fields = [value for value in attribute_raw.split(b"\x00") if value]
    if len(fields) != len(paths) * 6:
        raise RuntimeError("Git returned an invalid Linux payload attribute response")
    attributes: dict[str, dict[str, str]] = {path: {} for path in paths}
    for index in range(0, len(fields), 3):
        path, attribute, value = (
            field.decode("utf-8", errors="strict")
            for field in fields[index : index + 3]
        )
        if path not in attributes:
            raise RuntimeError(
                f"Git returned attributes for an unexpected path: {path}"
            )
        attributes[path][attribute] = value

    records: list[LinuxPayloadGitRecord] = []
    for path in paths:
        resolved = attributes[path]
        if set(resolved) != {"text", "eol"}:
            raise RuntimeError(f"Git did not resolve text and eol for {path}")
        index_content = _git_output(["show", f":{path}"])
        filtered: dict[bool, bytes] = {}
        for autocrlf in (True, False):
            value = str(autocrlf).lower()
            filtered[autocrlf] = _git_output(
                [
                    "-c",
                    f"core.autocrlf={value}",
                    "cat-file",
                    "--filters",
                    f"--path={path}",
                    f":{path}",
                ]
            )
        records.append(
            LinuxPayloadGitRecord(
                relative_path=path,
                text_attribute=resolved["text"],
                eol_attribute=resolved["eol"],
                index_content=index_content,
                worktree_content=(ROOT / path).read_bytes(),
                filtered_autocrlf_true=filtered[True],
                filtered_autocrlf_false=filtered[False],
            )
        )
    return tuple(records)


def validate_linux_payload_records(
    records: tuple[LinuxPayloadGitRecord, ...] | list[LinuxPayloadGitRecord],
    failures: list[str],
) -> None:
    for record in records:
        relative = record.relative_path
        if record.text_attribute == "set" and record.eol_attribute == "lf":
            contents = (
                ("index", record.index_content),
                ("worktree", record.worktree_content),
                ("core.autocrlf=true filter", record.filtered_autocrlf_true),
                ("core.autocrlf=false filter", record.filtered_autocrlf_false),
            )
            for source, content in contents:
                if b"\r" in content:
                    failures.append(
                        f"{relative}: CR byte in Linux text payload {source}"
                    )
                if b"\x00" in content:
                    failures.append(
                        f"{relative}: NUL byte in Linux text payload {source}"
                    )
            for source, content in contents[2:]:
                if content != record.index_content:
                    failures.append(
                        f"{relative}: {source} differs from the indexed Linux payload"
                    )
            continue
        if record.text_attribute == "unset":
            for source, content in (
                ("core.autocrlf=true filter", record.filtered_autocrlf_true),
                ("core.autocrlf=false filter", record.filtered_autocrlf_false),
            ):
                if content != record.index_content:
                    failures.append(
                        f"{relative}: {source} mutates an explicitly binary payload"
                    )
            continue
        failures.append(
            f"{relative}: Linux payload attributes are ambiguous "
            f"(text={record.text_attribute}, eol={record.eol_attribute}); "
            "require text eol=lf or explicit -text"
        )


def validate_linux_payload_policy_examples(failures: list[str]) -> None:
    binary_content = b"\x00\xff\r\n"
    explicit_binary = LinuxPayloadGitRecord(
        relative_path="agents/desktop/packaging/linux/future-payload.bin",
        text_attribute="unset",
        eol_attribute="unspecified",
        index_content=binary_content,
        worktree_content=binary_content,
        filtered_autocrlf_true=binary_content,
        filtered_autocrlf_false=binary_content,
    )
    binary_failures: list[str] = []
    validate_linux_payload_records([explicit_binary], binary_failures)
    if binary_failures:
        failures.append("Linux payload policy rejects an explicitly -text binary file")

    for description, content in (
        ("text", b"new text payload\n"),
        ("binary", binary_content),
    ):
        unclassified = LinuxPayloadGitRecord(
            relative_path=f"agents/desktop/packaging/linux/future-{description}",
            text_attribute="auto",
            eol_attribute="unspecified",
            index_content=content,
            worktree_content=content,
            filtered_autocrlf_true=content,
            filtered_autocrlf_false=content,
        )
        unclassified_failures: list[str] = []
        validate_linux_payload_records([unclassified], unclassified_failures)
        if len(unclassified_failures) != 1 or "attributes are ambiguous" not in (
            unclassified_failures[0]
        ):
            failures.append(
                f"Linux payload policy accepts an unclassified {description} file"
            )


def validate_linux_payload_git_policy(failures: list[str]) -> None:
    try:
        records = collect_linux_payload_git_records()
    except (OSError, RuntimeError, UnicodeError) as error:
        failures.append(f"Linux payload Git policy could not be validated: {error}")
        return
    validate_linux_payload_records(records, failures)


def files_to_scan() -> list[Path]:
    files = list(ROOT_FILES)
    for scan_root in SCAN_ROOTS:
        if scan_root.exists():
            files.extend(
                path
                for path in scan_root.rglob("*")
                if path.is_file()
                and path != Path(__file__).resolve()
                and (path.suffix in TEXT_SUFFIXES or path.name in {"Dockerfile"})
                and "node_modules" not in path.parts
                and "dist" not in path.parts
                and "build" not in path.parts
                and ".mypy_cache" not in path.parts
                and ".pytest_cache" not in path.parts
                and "__pycache__" not in path.parts
                and not any(part.startswith("pytest-cache-files-") for part in path.parts)
            )
    return files


def validate_contract_inventory(failures: list[str]) -> None:
    canonical = ROOT / "shared" / "contracts" / "schemas"
    packaged = ROOT / "backend" / "src" / "wto_backend" / "contract_data" / "schemas"
    canonical_names = {path.name for path in canonical.glob("*.schema.json")}
    packaged_names = {path.name for path in packaged.glob("*.schema.json")}
    if canonical_names != EXPECTED_CONTRACT_SCHEMAS:
        failures.append("shared/contracts/schemas: expected exact Phase 04 inventory of 14 schemas")
    if packaged_names != canonical_names:
        failures.append("backend contract_data schema inventory differs from canonical source")
    for name in canonical_names & packaged_names:
        if (canonical / name).read_bytes() != (packaged / name).read_bytes():
            failures.append(f"backend contract_data schema differs byte-for-byte: {name}")
    desktop = (
        ROOT
        / "agents"
        / "desktop"
        / "src"
        / "wto_desktop_agent"
        / "contract_data"
    )
    source_root = ROOT / "shared" / "contracts"
    expected_files = {
        path.relative_to(source_root)
        for directory in ("schemas", "catalog", "examples", "openapi")
        for path in (source_root / directory).rglob("*")
        if path.is_file()
    }
    actual_files = (
        {path.relative_to(desktop) for path in desktop.rglob("*") if path.is_file()}
        if desktop.exists()
        else set()
    )
    if actual_files != expected_files:
        failures.append("desktop contract_data inventory differs from canonical source")
    for relative in expected_files & actual_files:
        if (source_root / relative).read_bytes() != (desktop / relative).read_bytes():
            failures.append(
                f"desktop contract_data differs byte-for-byte: {relative.as_posix()}"
            )


def validate_gradle_wrapper(failures: list[str]) -> None:
    wrapper = ROOT / GRADLE_WRAPPER_JAR
    if not wrapper.is_file():
        failures.append(f"{GRADLE_WRAPPER_JAR.as_posix()}: Gradle wrapper JAR missing")
        return
    actual_hash = hashlib.sha256(wrapper.read_bytes()).hexdigest()
    if actual_hash != GRADLE_WRAPPER_JAR_SHA256:
        failures.append(f"{GRADLE_WRAPPER_JAR.as_posix()}: unexpected SHA-256")

    properties = wrapper.with_name("gradle-wrapper.properties").read_text(encoding="utf-8")
    if f"distributionSha256Sum={GRADLE_DISTRIBUTION_SHA256}" not in properties.splitlines():
        failures.append("gradle-wrapper.properties: distributionSha256Sum missing or changed")

    git = shutil.which("git")
    if git is None:
        failures.append("Git executable not found; cannot validate Gradle wrapper inclusion")
        return

    relative = GRADLE_WRAPPER_JAR.as_posix()
    ignored = subprocess.run(  # noqa: S603 - executable and arguments are fixed by the repository
        [git, "check-ignore", "--no-index", "--quiet", "--", relative],
        cwd=ROOT,
        check=False,
    )
    if ignored.returncode == 0:
        failures.append(f"{relative}: ignored by Git")
    elif ignored.returncode != 1:
        failures.append(f"{relative}: unable to determine Git ignore state")

    candidates = (
        subprocess.run(  # noqa: S603 - executable and arguments are fixed by the repository
            [git, "ls-files", "--cached", "--others", "--exclude-standard", "--", relative],
            cwd=ROOT,
            check=False,
            capture_output=True,
            text=True,
        )
    )
    included = {line.strip().replace("\\", "/") for line in candidates.stdout.splitlines()}
    if candidates.returncode != 0 or relative not in included:
        failures.append(f"{relative}: not included by Git as tracked or untracked candidate")


def validate_desktop_ci_policy(failures: list[str]) -> None:
    workflow_path = ROOT / ".github" / "workflows" / "ci.yml"
    workflow = workflow_path.read_text(encoding="utf-8")
    match = re.search(
        r"(?ms)^  desktop-agent-windows:\n(?P<body>.*?)(?=^  [A-Za-z0-9_-]+:\n|\Z)",
        workflow,
    )
    if match is None:
        failures.append("ci.yml: desktop-agent-windows job missing")
        return
    windows_job = match.group("body")
    if "agents/desktop[dev]" in windows_job:
        failures.append("ci.yml: Windows desktop job must not install the dev extra directly")
    positions = [windows_job.find(command) for command in WINDOWS_CI_INSTALL_COMMANDS]
    if any(position < 0 for position in positions) or positions != sorted(positions):
        failures.append("ci.yml: Windows desktop job must install locks, editable --no-deps, then pip check")
    if "cache-dependency-path: |" not in windows_job:
        failures.append("ci.yml: Windows desktop pip cache must use a dependency path block")
    for lock_path in (
        "agents/desktop/requirements.lock",
        "agents/desktop/requirements-dev.lock",
    ):
        if lock_path not in windows_job:
            failures.append(f"ci.yml: Windows desktop job does not consume {lock_path}")

    dockerfile = (ROOT / "agents" / "desktop" / "Dockerfile").read_text(encoding="utf-8")
    if "agents/desktop[dev]" in dockerfile:
        failures.append("agents/desktop/Dockerfile: Linux test image must not install dev extras")
    for required in (
        "--requirement agents/desktop/requirements-dev.lock",
        "--requirement agents/desktop/requirements.lock",
        "--no-deps --editable ./agents/desktop",
    ):
        if required not in dockerfile:
            failures.append(f"agents/desktop/Dockerfile: missing locked install policy {required}")


def validate_line_endings(failures: list[str]) -> None:
    powershell_scripts = [
        *(ROOT / "scripts").rglob("*.ps1"),
        *(ROOT / "agents").rglob("*.ps1"),
    ]
    for path in powershell_scripts:
        data = path.read_bytes()
        remainder = data.replace(b"\r\n", b"")
        if b"\r" in remainder or b"\n" in remainder:
            failures.append(f"{path.relative_to(ROOT).as_posix()}: expected CRLF-only line endings")
    for relative in LF_PATHS:
        if b"\r" in (ROOT / relative).read_bytes():
            failures.append(f"{relative.as_posix()}: expected LF-only line endings")


def main() -> None:
    failures: list[str] = []
    windows_path = re.compile(r"(?<![A-Za-z])[A-Za-z]:[\\/]")
    real_availability_reason = re.compile(r"[\"']availability_reason[\"']\s*[:=]")
    aggregate_support = re.compile(r"[\"']support[\"']\s*[:=]")
    hardcoded_dsn = re.compile(r"(?i)(postgres(?:ql)?|redis)://[^\s:@]+:[^\s@]+@")
    hardcoded_secret = re.compile(r"(?i)\b(password|token|secret)\b\s*[:=]\s*[\"'][^\"']{8,}[\"']")

    validate_contract_inventory(failures)
    validate_gradle_wrapper(failures)
    validate_desktop_ci_policy(failures)
    validate_line_endings(failures)
    validate_linux_payload_policy_examples(failures)
    validate_linux_payload_git_policy(failures)

    for path in files_to_scan():
        content = path.read_text(encoding="utf-8")
        relative = path.relative_to(ROOT).as_posix()
        negative_contract_fixture = relative.startswith(
            "shared/contracts/examples/invalid/"
        ) or relative.startswith(
            "backend/src/wto_backend/contract_data/examples/invalid/"
        ) or relative.startswith(
            "agents/desktop/src/wto_desktop_agent/contract_data/examples/invalid/"
        )
        if windows_path.search(content):
            failures.append(f"{relative}: absolute Windows path")
        if real_availability_reason.search(content):
            failures.append(f"{relative}: availability reason used as a real field")
        if aggregate_support.search(content):
            failures.append(f"{relative}: aggregate support field")
        for capability_id in () if negative_contract_fixture else FORBIDDEN_CAPABILITY_IDS:
            capability_pattern = re.compile(
                rf"(?<![A-Za-z0-9._-]){re.escape(capability_id)}(?![A-Za-z0-9._-])"
            )
            if capability_pattern.search(content):
                failures.append(f"{relative}: obsolete capability ID {capability_id}")
        if "tests/" not in relative and hardcoded_dsn.search(content):
            failures.append(f"{relative}: hardcoded credential-bearing DSN")
        if "tests/" not in relative and hardcoded_secret.search(content):
            failures.append(f"{relative}: possible hardcoded secret")
        if "simulated-agent-01" in content and relative.startswith("frontend/src/"):
            failures.append(f"{relative}: simulated inventory is hardcoded in the frontend")

    if failures:
        print("Repository validation failed:", file=sys.stderr)
        for failure in sorted(set(failures)):
            print(f"- {failure}", file=sys.stderr)
        raise SystemExit(1)
    print("Repository portability and normative guard validation passed.")


if __name__ == "__main__":
    main()
