from __future__ import annotations

import argparse
import json
import os
import struct
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, NoReturn, cast

_PROTOCOL_VERSION = 1
_MAX_FRAME_BYTES = 4 * 1024 * 1024
_MAX_ARGUMENTS = 4096
_MAX_ENVIRONMENT_ENTRIES = 8192
_GET_SESSION_ID = cast(Callable[[int], int] | None, getattr(os, "getsid", None))
_GET_PROCESS_GROUP = cast(Callable[[], int] | None, getattr(os, "getpgrp", None))


@dataclass(frozen=True)
class GuardMarker:
    nonce: str
    pid: int
    start_time: str
    session_id: int
    process_group_id: int

    def as_payload(self) -> dict[str, object]:
        return {
            "version": _PROTOCOL_VERSION,
            "nonce": self.nonce,
            "pid": self.pid,
            "start_time": self.start_time,
            "session_id": self.session_id,
            "process_group_id": self.process_group_id,
        }


@dataclass(frozen=True)
class GuardTarget:
    nonce: str
    executable: str
    argv: tuple[str, ...]
    cwd: str
    environment: dict[str, str]


def encode_frame(payload: dict[str, object]) -> bytes:
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    if not encoded or len(encoded) > _MAX_FRAME_BYTES:
        raise ValueError("spawn guard frame size is invalid")
    return struct.pack("!I", len(encoded)) + encoded


def read_frame(descriptor: int) -> dict[str, Any]:
    size = struct.unpack("!I", _read_exact(descriptor, 4))[0]
    if size <= 0 or size > _MAX_FRAME_BYTES:
        raise ValueError("spawn guard frame size is invalid")
    decoded = json.loads(_read_exact(descriptor, size).decode("utf-8"))
    if not isinstance(decoded, dict):
        raise ValueError("spawn guard frame must be an object")
    return decoded


def write_frame(descriptor: int, payload: dict[str, object]) -> None:
    _write_all(descriptor, encode_frame(payload))


def read_start_time(pid: int | str = "self") -> str:
    with open(f"/proc/{pid}/stat", encoding="ascii") as stream:  # noqa: PTH123
        text = stream.read()
    fields = text[text.rfind(")") + 2 :].split()
    if len(fields) <= 19:
        raise RuntimeError("spawn guard proc stat is incomplete")
    return fields[19]


def parse_target(payload: dict[str, Any]) -> GuardTarget:
    expected = {"version", "nonce", "executable", "argv", "cwd", "environment"}
    if set(payload) != expected or payload.get("version") != _PROTOCOL_VERSION:
        raise ValueError("spawn guard target payload is invalid")
    nonce = payload.get("nonce")
    executable = payload.get("executable")
    argv = payload.get("argv")
    cwd = payload.get("cwd")
    environment = payload.get("environment")
    if not isinstance(nonce, str) or len(nonce) != 64:
        raise ValueError("spawn guard nonce is invalid")
    if not isinstance(executable, str) or not os.path.isabs(executable):
        raise ValueError("spawn guard executable is invalid")
    if not isinstance(cwd, str) or not os.path.isabs(cwd):
        raise ValueError("spawn guard working directory is invalid")
    if (
        not isinstance(argv, list)
        or len(argv) > _MAX_ARGUMENTS
        or any(not isinstance(value, str) or "\0" in value for value in argv)
    ):
        raise ValueError("spawn guard argv is invalid")
    if (
        not isinstance(environment, dict)
        or len(environment) > _MAX_ENVIRONMENT_ENTRIES
        or any(
            not isinstance(key, str)
            or not isinstance(value, str)
            or not key
            or "=" in key
            or "\0" in key
            or "\0" in value
            for key, value in environment.items()
        )
    ):
        raise ValueError("spawn guard environment is invalid")
    if "\0" in executable or "\0" in cwd:
        raise ValueError("spawn guard paths are invalid")
    return GuardTarget(
        nonce=nonce,
        executable=executable,
        argv=tuple(argv),
        cwd=cwd,
        environment=dict(environment),
    )


def parse_release(payload: dict[str, Any], nonce: str) -> None:
    if payload != {"version": _PROTOCOL_VERSION, "nonce": nonce, "command": "release"}:
        raise ValueError("spawn guard release is invalid")


def _read_exact(descriptor: int, size: int) -> bytes:
    result = bytearray()
    while len(result) < size:
        chunk = os.read(descriptor, size - len(result))
        if not chunk:
            raise EOFError("spawn guard channel closed")
        result.extend(chunk)
    return bytes(result)


def _write_all(descriptor: int, payload: bytes) -> None:
    view = memoryview(payload)
    while view:
        written = os.write(descriptor, view)
        if written <= 0:
            raise BrokenPipeError("spawn guard channel closed")
        view = view[written:]


def _fail(message: str, status: int = 125) -> NoReturn:
    try:
        os.write(2, f"spawn guard failed: {message}\n".encode("ascii", errors="replace"))
    finally:
        raise SystemExit(status)


def run(marker_descriptor: int, control_descriptor: int) -> NoReturn:
    try:
        target = parse_target(read_frame(control_descriptor))
        if _GET_SESSION_ID is None or _GET_PROCESS_GROUP is None:
            raise RuntimeError("spawn guard session primitives are unavailable")
        pid = os.getpid()
        marker = GuardMarker(
            nonce=target.nonce,
            pid=pid,
            start_time=read_start_time(),
            session_id=_GET_SESSION_ID(0),
            process_group_id=_GET_PROCESS_GROUP(),
        )
        write_frame(marker_descriptor, marker.as_payload())
        os.close(marker_descriptor)
        marker_descriptor = -1
        parse_release(read_frame(control_descriptor), target.nonce)
        os.close(control_descriptor)
        control_descriptor = -1
        os.chdir(target.cwd)
        # This is the sole fixed guard-to-allowlisted-target transition; no
        # shell or command-line construction is involved.
        os.execve(  # noqa: S606
            target.executable,
            [target.executable, *target.argv],
            target.environment,
        )
    except SystemExit:
        raise
    except BaseException as error:
        _fail(type(error).__name__)
    finally:
        for descriptor in (marker_descriptor, control_descriptor):
            if descriptor >= 0:
                try:
                    os.close(descriptor)
                except OSError:
                    pass


def main() -> NoReturn:
    parser = argparse.ArgumentParser(add_help=False, allow_abbrev=False)
    parser.add_argument("--marker-fd", required=True, type=int)
    parser.add_argument("--control-fd", required=True, type=int)
    arguments = parser.parse_args()
    run(arguments.marker_fd, arguments.control_fd)


if __name__ == "__main__":
    main()
