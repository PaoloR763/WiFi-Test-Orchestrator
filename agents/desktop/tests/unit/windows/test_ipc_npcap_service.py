from __future__ import annotations

import inspect
import re
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

import pytest
from pydantic import ValidationError

from wto_desktop_agent.platforms.windows.acl import directory_sddl, pipe_sddl
from wto_desktop_agent.platforms.windows.enrollment_ipc import (
    MAX_FRAME_BYTES,
    EnrollmentIpcRequest,
    EnrollmentPipeServer,
    _read_exact,
    decode_frame,
    encode_frame,
)
from wto_desktop_agent.platforms.windows.npcap import (
    map_capture_devices,
    parse_dumpcap_devices,
)


def test_enrollment_ipc_is_closed_and_bounded() -> None:
    request = EnrollmentIpcRequest(
        schema_version="1.0.0",
        operation="enroll",
        display_name="lab-agent",
        enrollment_token="x" * 32,
    )
    assert decode_frame(encode_frame(request))["operation"] == "enroll"
    with pytest.raises(ValidationError):
        EnrollmentIpcRequest.model_validate(
            {
                "schema_version": "1.0.0",
                "operation": "shell",
                "display_name": "x",
                "enrollment_token": "x" * 32,
            }
        )
    with pytest.raises(ValueError, match="length"):
        decode_frame((MAX_FRAME_BYTES + 1).to_bytes(4, "big"))


def test_enrollment_ipc_read_timeout_is_bounded(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setitem(sys.modules, "win32file", SimpleNamespace())
    monkeypatch.setitem(sys.modules, "win32pipe", SimpleNamespace())
    with pytest.raises(TimeoutError):
        _read_exact(object(), 1, 0.0)


def test_enrollment_pipe_create_mode_rejects_remote_clients(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class SecurityAttributes:
        SECURITY_DESCRIPTOR: object

    reject_remote_clients = 0x00000008
    create_named_pipe = Mock(side_effect=RuntimeError("stop after CreateNamedPipe"))
    monkeypatch.setitem(
        sys.modules, "pywintypes", SimpleNamespace(SECURITY_ATTRIBUTES=SecurityAttributes)
    )
    monkeypatch.setitem(sys.modules, "win32event", SimpleNamespace())
    monkeypatch.setitem(sys.modules, "win32file", SimpleNamespace(FILE_FLAG_OVERLAPPED=0x40000000))
    monkeypatch.setitem(
        sys.modules,
        "win32pipe",
        SimpleNamespace(
            CreateNamedPipe=create_named_pipe,
            PIPE_ACCESS_DUPLEX=0x00000003,
            PIPE_READMODE_BYTE=0x00000000,
            PIPE_REJECT_REMOTE_CLIENTS=reject_remote_clients,
            PIPE_TYPE_BYTE=0x00000000,
            PIPE_WAIT=0x00000000,
        ),
    )
    monkeypatch.setitem(
        sys.modules,
        "win32security",
        SimpleNamespace(
            ConvertStringSecurityDescriptorToSecurityDescriptor=Mock(return_value=object()),
            SDDL_REVISION_1=1,
        ),
    )

    server = EnrollmentPipeServer(AsyncMock(), "S-1-5-80-123")
    with pytest.raises(RuntimeError, match="stop after CreateNamedPipe"):
        server.serve_once()

    pipe_mode = create_named_pipe.call_args.args[2]
    assert pipe_mode & reject_remote_clients == reject_remote_clients


def test_enrollment_pipe_remote_client_rejection_source_guardrail() -> None:
    source = inspect.getsource(EnrollmentPipeServer.serve_once)
    assert "win32pipe.PIPE_REJECT_REMOTE_CLIENTS" in source


def test_acl_sddl_only_names_system_admins_and_service() -> None:
    sid = "S-1-5-80-123"
    assert "SY" in pipe_sddl(sid) and "BA" in pipe_sddl(sid) and sid in pipe_sddl(sid)
    assert sid in directory_sddl(sid, writable=True)
    assert "WD" not in pipe_sddl(sid)


def test_dumpcap_mapping_is_guid_based_and_ambiguous_fails_closed() -> None:
    raw = (
        b"1. \\Device\\NPF_{11111111-1111-4111-8111-111111111111}\tWi-Fi\n"
        b"2. NPF_Loopback\tAdapter for loopback traffic capture\n"
    )
    devices = parse_dumpcap_devices(raw)
    mapping = map_capture_devices(devices, {"11111111-1111-4111-8111-111111111111"})
    assert mapping["11111111-1111-4111-8111-111111111111"] is not None
    assert any(device.loopback for device in devices)
    mapping = map_capture_devices(
        [devices[0], devices[0]], {"11111111-1111-4111-8111-111111111111"}
    )
    assert mapping["11111111-1111-4111-8111-111111111111"] is None


def test_packaging_scripts_do_not_contain_capture_or_iperf_commands() -> None:
    root = Path(__file__).parents[5]
    scripts = "\n".join(
        path.read_text(encoding="utf-8") for path in (root / "scripts" / "windows").glob("*.ps1")
    )
    assert "iperf3" not in scripts.lower()
    assert "dumpcap" not in scripts.lower()
    assert not re.search(r"(?im)^\s*&\s+.*dumpcap.*(?:^|\s)-I(?:\s|$)", scripts)
