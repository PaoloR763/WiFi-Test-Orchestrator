from __future__ import annotations

import re
import sys
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
            )
    return files


def main() -> None:
    failures: list[str] = []
    windows_path = re.compile(r"(?<![A-Za-z])[A-Za-z]:[\\/]")
    real_availability_reason = re.compile(r"[\"']availability_reason[\"']\s*[:=]")
    aggregate_support = re.compile(r"[\"']support[\"']\s*[:=]")
    hardcoded_dsn = re.compile(r"(?i)(postgres(?:ql)?|redis)://[^\s:@]+:[^\s@]+@")
    hardcoded_secret = re.compile(
        r"(?i)\b(password|token|secret)\b\s*[:=]\s*[\"'][^\"']{8,}[\"']"
    )

    for path in files_to_scan():
        content = path.read_text(encoding="utf-8")
        relative = path.relative_to(ROOT).as_posix()
        if windows_path.search(content):
            failures.append(f"{relative}: absolute Windows path")
        if real_availability_reason.search(content):
            failures.append(f"{relative}: availability reason used as a real field")
        if aggregate_support.search(content):
            failures.append(f"{relative}: aggregate support field")
        for capability_id in FORBIDDEN_CAPABILITY_IDS:
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
