from __future__ import annotations

import os
import signal
import sys
import time

PAYLOAD = b"\x0a\x0d\x0d\x0aWTO-FAKE-DUMPCAP\x00\xff"
DIAGNOSTIC = "wto-fake-dumpcap-diagnostic"


def _validate_argv(argv: list[str]) -> None:
    if len(argv) != 16:
        raise ValueError("unexpected dumpcap argument count")
    if (
        argv[0:2] != ["-q", "-i"]
        or not argv[2]
        or argv[3:7] != ["-I", "-y", "IEEE802_11_RADIO", "-F"]
        or argv[7] not in {"pcap", "pcapng"}
        or argv[8] != "-s"
        or not argv[9].isdigit()
        or argv[10] != "-a"
        or not argv[11].startswith("duration:")
        or not argv[11][9:].isdigit()
        or argv[12] != "-a"
        or not argv[13].startswith("filesize:")
        or not argv[13][9:].isdigit()
        or argv[14:16] != ["-w", "-"]
    ):
        raise ValueError("unexpected dumpcap arguments")


def _open_descriptors() -> str:
    try:
        return ",".join(sorted(os.listdir("/proc/self/fd"), key=int))
    except OSError:
        return "unavailable"


def main() -> int:
    try:
        _validate_argv(sys.argv[1:])
    except ValueError as error:
        os.write(2, f"{DIAGNOSTIC}:argv:{error}\n".encode("ascii"))
        return 64
    mode = os.environ.get("WTO_FAKE_DUMPCAP_MODE", "normal")
    os.write(2, f"{DIAGNOSTIC}:mode={mode}:fds={_open_descriptors()}\n".encode("ascii"))
    if mode == "nonzero":
        return 7
    if mode == "oversize":
        os.write(1, PAYLOAD * 1024)
        return 0
    if mode == "ignore-term":
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        ready = os.environ.get("WTO_FAKE_DUMPCAP_READY")
        if ready:
            descriptor = os.open(ready, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            os.close(descriptor)
        while True:
            time.sleep(1)
    if mode == "block":
        ready = os.environ.get("WTO_FAKE_DUMPCAP_READY")
        if ready:
            descriptor = os.open(ready, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            os.close(descriptor)
        while True:
            time.sleep(1)
    if mode != "normal":
        return 65
    os.write(1, PAYLOAD)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
