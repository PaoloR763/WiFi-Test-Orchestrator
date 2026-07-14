from __future__ import annotations

import json
import logging
import struct
import time
from collections.abc import Callable, Coroutine
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

MAX_FRAME_BYTES = 65_536
PIPE_NAME = r"\\.\pipe\WiFiTestOrchestrator.Agent.Enrollment.v1"
LOGGER = logging.getLogger(__name__)


class EnrollmentIpcRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    schema_version: Literal["1.0.0"]
    operation: Literal["enroll"]
    display_name: str = Field(min_length=1, max_length=128)
    enrollment_token: str = Field(min_length=16, max_length=512)


class EnrollmentIpcResponse(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    schema_version: Literal["1.0.0"] = "1.0.0"
    status: Literal["enrolled", "failed"]
    agent_id: str | None = None
    error_code: str | None = None


def encode_frame(payload: BaseModel | dict[str, object]) -> bytes:
    document = payload.model_dump(mode="json") if isinstance(payload, BaseModel) else payload
    body = json.dumps(document, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    if not body or len(body) > MAX_FRAME_BYTES:
        raise ValueError("enrollment IPC frame exceeds limit")
    return struct.pack(">I", len(body)) + body


def decode_frame(frame: bytes) -> dict[str, object]:
    if len(frame) < 4:
        raise ValueError("enrollment IPC frame is truncated")
    length = struct.unpack(">I", frame[:4])[0]
    if length <= 0 or length > MAX_FRAME_BYTES or len(frame) != length + 4:
        raise ValueError("enrollment IPC frame length is invalid")
    try:
        value = json.loads(frame[4:].decode("utf-8", errors="strict"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("enrollment IPC frame is invalid JSON") from error
    if not isinstance(value, dict):
        raise ValueError("enrollment IPC payload must be an object")
    return value


def _read_exact(handle: Any, length: int, timeout_seconds: float) -> bytes:
    """Read a byte-mode pipe frame without assuming a single complete ReadFile."""
    import win32file
    import win32pipe

    deadline = time.monotonic() + timeout_seconds
    chunks: list[bytes] = []
    remaining = length
    while remaining:
        if time.monotonic() >= deadline:
            raise TimeoutError("enrollment IPC frame read timed out")
        _, available, _ = win32pipe.PeekNamedPipe(handle, 0)
        if available <= 0:
            time.sleep(0.01)
            continue
        _, chunk = win32file.ReadFile(handle, min(remaining, available))
        data = bytes(chunk)
        if not data:
            raise ConnectionError("enrollment IPC peer closed a partial frame")
        chunks.append(data)
        remaining -= len(data)
    return b"".join(chunks)


class EnrollmentPipeServer:
    def __init__(
        self,
        handler: Callable[[EnrollmentIpcRequest], Coroutine[Any, Any, EnrollmentIpcResponse]],
        service_sid: str,
    ) -> None:
        self.handler = handler
        self.service_sid = service_sid

    def serve_once(self, timeout_seconds: float = 30.0) -> None:
        import asyncio

        import pywintypes
        import win32event
        import win32file
        import win32pipe
        import win32security

        from wto_desktop_agent.platforms.windows.acl import pipe_sddl

        descriptor = win32security.ConvertStringSecurityDescriptorToSecurityDescriptor(
            pipe_sddl(self.service_sid), win32security.SDDL_REVISION_1
        )
        attributes = pywintypes.SECURITY_ATTRIBUTES()
        attributes.SECURITY_DESCRIPTOR = descriptor
        pipe = win32pipe.CreateNamedPipe(
            PIPE_NAME,
            win32pipe.PIPE_ACCESS_DUPLEX | win32file.FILE_FLAG_OVERLAPPED,
            win32pipe.PIPE_TYPE_BYTE
            | win32pipe.PIPE_READMODE_BYTE
            | win32pipe.PIPE_WAIT
            | win32pipe.PIPE_REJECT_REMOTE_CLIENTS,
            1,
            MAX_FRAME_BYTES + 4,
            MAX_FRAME_BYTES + 4,
            int(timeout_seconds * 1000),
            attributes,
        )
        connected = win32event.CreateEvent(None, True, False, None)
        overlapped = pywintypes.OVERLAPPED()
        overlapped.hEvent = connected
        try:
            try:
                win32pipe.ConnectNamedPipe(pipe, overlapped)
            except Exception as error:
                if getattr(error, "winerror", None) != 997:
                    raise
            if win32event.WaitForSingleObject(connected, int(timeout_seconds * 1000)) != 0:
                raise TimeoutError("enrollment IPC connection timed out")
            header = _read_exact(pipe, 4, timeout_seconds)
            length = struct.unpack(">I", header)[0]
            if length <= 0 or length > MAX_FRAME_BYTES:
                raise ValueError("enrollment IPC frame length is invalid")
            body = _read_exact(pipe, length, timeout_seconds)
            request = EnrollmentIpcRequest.model_validate(decode_frame(header + body))
            response: EnrollmentIpcResponse = asyncio.run(self.handler(request))
            win32file.WriteFile(pipe, encode_frame(response))
            win32file.FlushFileBuffers(pipe)
        finally:
            try:
                win32pipe.DisconnectNamedPipe(pipe)
            except Exception as error:
                LOGGER.debug(
                    "named pipe was already disconnected", extra={"error": type(error).__name__}
                )
            win32file.CloseHandle(pipe)


def send_enrollment_request(
    request: EnrollmentIpcRequest, timeout_seconds: float = 30.0
) -> EnrollmentIpcResponse:
    import win32file
    import win32pipe

    win32pipe.WaitNamedPipe(PIPE_NAME, int(timeout_seconds * 1000))
    handle = win32file.CreateFile(
        PIPE_NAME,
        win32file.GENERIC_READ | win32file.GENERIC_WRITE,
        0,
        None,
        win32file.OPEN_EXISTING,
        0,
        None,
    )
    try:
        win32file.WriteFile(handle, encode_frame(request))
        header = _read_exact(handle, 4, timeout_seconds)
        length = struct.unpack(">I", header)[0]
        if length <= 0 or length > MAX_FRAME_BYTES:
            raise ValueError("enrollment IPC response length is invalid")
        body = _read_exact(handle, length, timeout_seconds)
        return EnrollmentIpcResponse.model_validate(decode_frame(header + body))
    finally:
        win32file.CloseHandle(handle)
