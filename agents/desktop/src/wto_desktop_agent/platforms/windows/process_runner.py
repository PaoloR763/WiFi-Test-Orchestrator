from __future__ import annotations

import asyncio
import ctypes
import math
from ctypes import wintypes
from dataclasses import dataclass
from typing import Any, Protocol, cast

import win32api
import win32con
import win32job
import win32process

from wto_desktop_agent.platforms.common import AllowlistedProcessRunner, CommandSpec

_TH32CS_SNAPTHREAD = 0x00000004
_INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value


class _ThreadEntry32(ctypes.Structure):
    _fields_ = [
        ("dwSize", wintypes.DWORD),
        ("cntUsage", wintypes.DWORD),
        ("th32ThreadID", wintypes.DWORD),
        ("th32OwnerProcessID", wintypes.DWORD),
        ("tpBasePri", wintypes.LONG),
        ("tpDeltaPri", wintypes.LONG),
        ("dwFlags", wintypes.DWORD),
    ]


_ctypes_windows = cast(Any, ctypes)
_kernel32 = _ctypes_windows.WinDLL("kernel32", use_last_error=True)
_kernel32.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
_kernel32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
_kernel32.Thread32First.argtypes = [wintypes.HANDLE, ctypes.POINTER(_ThreadEntry32)]
_kernel32.Thread32First.restype = wintypes.BOOL
_kernel32.Thread32Next.argtypes = [wintypes.HANDLE, ctypes.POINTER(_ThreadEntry32)]
_kernel32.Thread32Next.restype = wintypes.BOOL
_kernel32.GetProcessIdOfThread.argtypes = [wintypes.HANDLE]
_kernel32.GetProcessIdOfThread.restype = wintypes.DWORD
_kernel32.GetProcessId.argtypes = [wintypes.HANDLE]
_kernel32.GetProcessId.restype = wintypes.DWORD
_kernel32.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
_kernel32.WaitForSingleObject.restype = wintypes.DWORD
_kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
_kernel32.CloseHandle.restype = wintypes.BOOL

_WAIT_OBJECT_0 = 0x00000000
_WAIT_TIMEOUT = 0x00000102


class _NativeHandle(Protocol):
    def Close(self) -> None: ...

    def __int__(self) -> int: ...


@dataclass(slots=True)
class ProcessContext:
    """Native ownership for one spawn, keyed only by its opaque execution token."""

    execution_token: object
    job: _NativeHandle | None
    deadline: float = math.inf
    process: asyncio.subprocess.Process | None = None
    process_id: int | None = None
    suspended_thread: _NativeHandle | None = None
    assigned: bool = False
    termination_requested: bool = False
    released: bool = False


class WindowsProcessRunner(AllowlistedProcessRunner):
    def __init__(self, commands: dict[str, CommandSpec] | None = None) -> None:
        super().__init__(commands or {})
        self._contexts: dict[object, ProcessContext] = {}

    async def start_process(
        self,
        spec: CommandSpec,
        argv: list[str],
        environment: dict[str, str],
        *,
        execution_token: object,
        deadline: float | None = None,
        stdout_descriptor: int | None = None,
    ) -> asyncio.subprocess.Process:
        if stdout_descriptor is not None:
            raise RuntimeError("Windows process runner does not allow caller-owned stdout handles")
        absolute_deadline = math.inf if deadline is None else deadline
        self._ensure_before_deadline(absolute_deadline, "Job Object creation")
        job = self._create_job()
        if execution_token in self._contexts:
            try:
                job.Close()
            except BaseException as close_error:
                duplicate_error = RuntimeError("execution token is already active")
                duplicate_error.add_note(f"Job Object close also failed: {close_error!r}")
                raise duplicate_error from None
            raise RuntimeError("execution token is already active")
        context = ProcessContext(
            execution_token=execution_token,
            job=job,
            deadline=absolute_deadline,
        )
        self._contexts[execution_token] = context
        creation_task: asyncio.Task[Any] | None = None
        try:
            self._ensure_before_deadline(context.deadline, "process creation")
            creation_task = self._create_managed_task(
                asyncio.create_subprocess_exec(
                    str(spec.executable),
                    *argv,
                    cwd=spec.cwd,
                    env=environment,
                    stdin=asyncio.subprocess.DEVNULL,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                    creationflags=(win32con.CREATE_NEW_PROCESS_GROUP | win32con.CREATE_SUSPENDED),
                ),
                [],
            )
            # Waiting through a separate task prevents cancellation of run() from
            # interrupting asyncio between CreateProcess and returning its process
            # object. The exception path below cancels and drains this task under
            # the same bounded cleanup grace, recovering the object if creation won
            # the race so its original handle can still be terminated.
            await asyncio.wait({creation_task})
            process = cast(asyncio.subprocess.Process, creation_task.result())
            context.process = process
            context.process_id = process.pid
            # Deliver cancellation after CreateProcess returned while the
            # original process is still suspended and owned by this context.
            await self._after_process_created(context)
            self._ensure_before_deadline(context.deadline, "process creation")
            if context.job is None:
                raise RuntimeError("process context was released during process creation")
            process_handle = self._process_handle(process)
            self._validate_process_handle(process_handle, process.pid)
            self._ensure_before_deadline(context.deadline, "process validation")
            self._assign_job(context.job, process_handle)
            context.assigned = True
            self._ensure_before_deadline(context.deadline, "Job Object assignment")
            context.suspended_thread = self._open_initial_thread(process.pid, process_handle)
            self._ensure_before_deadline(context.deadline, "initial thread validation")
            self._resume_initial_thread(context, process_handle)
            return process
        except BaseException as primary_error:
            primary_traceback = primary_error.__traceback__
            cleanup_deadline = asyncio.get_running_loop().time() + self._cleanup_grace_seconds
            operation_deadline = max(
                asyncio.get_running_loop().time(),
                cleanup_deadline - self._cleanup_force_close_reserve_seconds,
            )
            if creation_task is not None and context.process is None:
                if not creation_task.done():
                    creation_task.cancel()
                creation_error, creation_cancellation, creation_timed_out = (
                    await self._wait_for_protected_task(
                        creation_task,
                        deadline=operation_deadline,
                    )
                )
                if creation_timed_out:
                    # A native CreateProcess can win the race after our bounded
                    # wait. Keep a completion owner which uses the returned
                    # process object's original handle; a late PID is never
                    # reopened and the suspended child is never resumed.
                    creation_task.add_done_callback(
                        lambda task: self._cleanup_late_creation(
                            task,
                            context,
                        )
                    )
                    primary_error.add_note(
                        "CreateProcess task did not settle within the cleanup grace"
                    )
                elif creation_error is None and not creation_task.cancelled():
                    recovered_process = cast(
                        asyncio.subprocess.Process,
                        creation_task.result(),
                    )
                    context.process = recovered_process
                    context.process_id = recovered_process.pid
                elif not isinstance(creation_error, asyncio.CancelledError):
                    primary_error.add_note(
                        f"CreateProcess task cleanup also failed: {creation_error!r}"
                    )
                if creation_cancellation is not None:
                    primary_error.add_note("CreateProcess task cleanup was also cancelled")
            cleanup_awaitable = self._cleanup_failed_spawn(
                context,
                deadline=cleanup_deadline,
            )
            try:
                cleanup_task = asyncio.create_task(cleanup_awaitable)
            except BaseException as task_error:
                cleanup_awaitable.close()
                primary_error.add_note(f"spawn cleanup task creation also failed: {task_error!r}")
                try:
                    self._force_release_context(context)
                except BaseException as force_error:
                    primary_error.add_note(f"spawn force-cleanup also failed: {force_error!r}")
                raise primary_error.with_traceback(primary_traceback) from task_error
            cleanup_task.add_done_callback(self._consume_future_result)
            cleanup_error, cleanup_cancellation, timed_out = await self._wait_for_protected_task(
                cleanup_task,
                deadline=operation_deadline,
            )
            if timed_out:
                cleanup_task.cancel()
                try:
                    self._force_release_context(context)
                except BaseException as error:
                    primary_error.add_note(f"spawn force-cleanup also failed: {error!r}")
                primary_error.add_note("spawn cleanup exceeded the cleanup grace")
                drain_error, drain_cancellation, drain_timed_out = (
                    await self._wait_for_protected_task(
                        cleanup_task,
                        deadline=cleanup_deadline,
                    )
                )
                cleanup_cancellation = cleanup_cancellation or drain_cancellation
                if drain_timed_out:
                    primary_error.add_note("spawn cleanup task remained pending after force-close")
                elif drain_error is not None and not isinstance(
                    drain_error, asyncio.CancelledError
                ):
                    primary_error.add_note(f"spawn cleanup drain also failed: {drain_error!r}")
            elif cleanup_error is not None:
                primary_error.add_note(f"spawn cleanup also failed: {cleanup_error!r}")
            if cleanup_cancellation is not None:
                primary_error.add_note("spawn cleanup was also cancelled")
            raise primary_error.with_traceback(primary_traceback) from None

    async def _after_process_created(self, context: ProcessContext) -> None:
        del context
        await asyncio.sleep(0)

    def _cleanup_late_creation(
        self,
        task: asyncio.Future[Any],
        context: ProcessContext,
    ) -> None:
        if task.cancelled():
            return
        try:
            process = cast(asyncio.subprocess.Process, task.result())
            if context.process is None:
                context.process = process
                context.process_id = process.pid
            self._force_close_process_once(process)
        except BaseException:
            # The primary caller has already returned by definition. Consume
            # every completion outcome and emit no potentially private native
            # error. The normal path above still uses only the original handle.
            return

    async def terminate(self, process: asyncio.subprocess.Process) -> None:
        context = self._context_for_process(process)
        if context is None:
            await super().terminate(process)
            return
        errors: list[BaseException] = []
        try:
            self._close_suspended_thread(context)
        except BaseException as error:
            errors.append(error)
        try:
            self._terminate_job_once(context)
        except BaseException as error:
            errors.append(error)
        try:
            await process.wait()
        except BaseException as error:
            errors.append(error)
        if errors:
            raise errors[0]

    def after_finish(self, process: asyncio.subprocess.Process) -> None:
        context = self._context_for_process(process)
        if context is None:
            return
        errors: list[BaseException] = []
        try:
            self._close_suspended_thread(context)
        except BaseException as error:
            errors.append(error)
        try:
            self._terminate_job_once(context)
        except BaseException as error:
            errors.append(error)
        if errors:
            raise errors[0]

    async def wait_after_finish(self, process: asyncio.subprocess.Process) -> None:
        context = self._context_for_process(process)
        if context is None:
            return
        primary_error: BaseException | None = None
        try:
            if context.job is not None:
                await self._wait_for_job_empty(context.job)
        except BaseException as error:
            primary_error = error
        finally:
            try:
                self._close_job(context)
            except BaseException as close_error:
                if primary_error is not None:
                    primary_error.add_note(f"Job Object close also failed: {close_error!r}")
                else:
                    primary_error = close_error
            self._unregister_context(context)
        if primary_error is not None:
            raise primary_error

    def _create_job(self) -> _NativeHandle:
        job = win32job.CreateJobObject(None, "")
        try:
            information = win32job.QueryInformationJobObject(
                job, win32job.JobObjectExtendedLimitInformation
            )
            information["BasicLimitInformation"][
                "LimitFlags"
            ] |= win32job.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
            win32job.SetInformationJobObject(
                job, win32job.JobObjectExtendedLimitInformation, information
            )
            return cast(_NativeHandle, job)
        except BaseException as primary_error:
            try:
                job.Close()
            except BaseException as close_error:
                primary_error.add_note(f"Job Object close also failed: {close_error!r}")
            raise

    def _assign_job(self, job: _NativeHandle, process_handle: int) -> None:
        # CreateProcess granted this original handle before the suspended process
        # could execute. Never reopen the process by PID for containment.
        win32job.AssignProcessToJobObject(job, process_handle)

    def _open_initial_thread(self, process_id: int, process_handle: int) -> _NativeHandle:
        self._validate_process_handle(process_handle, process_id)
        thread_ids = self._thread_ids(process_id)
        if len(thread_ids) != 1:
            raise RuntimeError("suspended process must expose exactly one initial thread")
        thread = win32api.OpenThread(
            win32con.THREAD_SUSPEND_RESUME | win32con.THREAD_QUERY_LIMITED_INFORMATION,
            False,
            thread_ids[0],
        )
        owner_process_id = int(_kernel32.GetProcessIdOfThread(int(thread)))
        try:
            self._validate_process_handle(process_handle, process_id)
        except BaseException as primary_error:
            try:
                thread.Close()
            except BaseException as close_error:
                primary_error.add_note(f"Initial thread handle close also failed: {close_error!r}")
            raise
        if owner_process_id != process_id:
            owner_error = RuntimeError("initial thread does not belong to the suspended process")
            try:
                thread.Close()
            except BaseException as close_error:
                owner_error.add_note(f"Initial thread handle close also failed: {close_error!r}")
            raise owner_error
        return cast(_NativeHandle, thread)

    def _resume_initial_thread(self, context: ProcessContext, process_handle: int) -> None:
        process = context.process
        thread = context.suspended_thread
        if process is None or context.process_id is None:
            raise RuntimeError("suspended process context is incomplete")
        if thread is None:
            raise RuntimeError("suspended process thread handle is unavailable")
        # Clear ownership before any native call so every failure path closes
        # this exact handle at most once.
        context.suspended_thread = None
        primary_error: BaseException | None = None
        try:
            self._ensure_before_deadline(context.deadline, "initial thread resume")
            self._validate_process_handle(process_handle, context.process_id)
            owner_process_id = int(_kernel32.GetProcessIdOfThread(int(thread)))
            if owner_process_id != context.process_id:
                raise RuntimeError("suspended thread owner changed before resume")
            self._ensure_before_deadline(context.deadline, "initial thread resume")
            previous_suspend_count = int(win32process.ResumeThread(thread))
            if previous_suspend_count != 1:
                raise RuntimeError("initial process thread had an unexpected suspend count")
            self._ensure_before_deadline(context.deadline, "initial thread resume")
        except BaseException as error:
            primary_error = error
        finally:
            try:
                thread.Close()
            except BaseException as close_error:
                if primary_error is not None:
                    primary_error.add_note(
                        f"suspended thread handle close also failed: {close_error!r}"
                    )
                else:
                    primary_error = close_error
        if primary_error is not None:
            raise primary_error

    def _process_handle(self, process: asyncio.subprocess.Process) -> int:
        transport = cast(Any, getattr(process, "_transport", None))
        popen = getattr(transport, "_proc", None)
        process_handle = getattr(popen, "_handle", None)
        if process_handle is None:
            raise RuntimeError("original CreateProcess handle is unavailable")
        return int(process_handle)

    @staticmethod
    def _ensure_before_deadline(deadline: float, stage: str) -> None:
        if not math.isfinite(deadline):
            return
        if asyncio.get_running_loop().time() >= deadline:
            raise TimeoutError(f"allowlisted process timed out during {stage}")

    def _validate_process_handle(self, process_handle: int, process_id: int) -> None:
        if int(_kernel32.GetProcessId(process_handle)) != process_id:
            raise RuntimeError("original process handle identity changed")
        wait_result = int(_kernel32.WaitForSingleObject(process_handle, 0))
        if wait_result == _WAIT_TIMEOUT:
            return
        if wait_result == _WAIT_OBJECT_0:
            raise RuntimeError("suspended process exited before containment completed")
        error_code = int(_ctypes_windows.get_last_error())
        raise OSError(error_code, "failed to inspect suspended process handle")

    def _thread_ids(self, process_id: int) -> list[int]:
        snapshot = _kernel32.CreateToolhelp32Snapshot(_TH32CS_SNAPTHREAD, 0)
        if snapshot == _INVALID_HANDLE_VALUE:
            error_code = int(_ctypes_windows.get_last_error())
            raise OSError(error_code, "CreateToolhelp32Snapshot failed")
        try:
            entry = _ThreadEntry32()
            entry.dwSize = ctypes.sizeof(_ThreadEntry32)
            result: list[int] = []
            available = bool(_kernel32.Thread32First(snapshot, ctypes.byref(entry)))
            while available:
                if int(entry.th32OwnerProcessID) == process_id:
                    result.append(int(entry.th32ThreadID))
                available = bool(_kernel32.Thread32Next(snapshot, ctypes.byref(entry)))
            return result
        finally:
            _kernel32.CloseHandle(snapshot)

    def _context_for_process(self, process: asyncio.subprocess.Process) -> ProcessContext | None:
        # PID is deliberately absent: contexts retain the process strongly and
        # are matched only by Python object identity.
        return next(
            (context for context in self._contexts.values() if context.process is process),
            None,
        )

    def _unregister_context(self, context: ProcessContext) -> None:
        if self._contexts.get(context.execution_token) is context:
            self._contexts.pop(context.execution_token)

    def _close_suspended_thread(self, context: ProcessContext) -> None:
        thread = context.suspended_thread
        context.suspended_thread = None
        if thread is not None:
            thread.Close()

    def _terminate_job_once(self, context: ProcessContext) -> None:
        job = context.job
        if job is None or context.termination_requested:
            return
        context.termination_requested = True
        win32job.TerminateJobObject(job, 1)

    def _close_job(self, context: ProcessContext) -> None:
        job = context.job
        context.job = None
        if job is not None:
            job.Close()

    async def _cleanup_failed_spawn(
        self,
        context: ProcessContext,
        *,
        deadline: float,
    ) -> None:
        errors: list[BaseException] = []
        try:
            self._force_release_context(context)
        except BaseException as error:
            errors.append(error)
        process = context.process
        if process is not None:
            wait_task = asyncio.create_task(process.wait())
            wait_task.add_done_callback(self._consume_future_result)
            wait_error, cancellation, timed_out = await self._wait_for_protected_task(
                wait_task,
                deadline=max(
                    asyncio.get_running_loop().time(),
                    deadline - self._cleanup_force_close_reserve_seconds,
                ),
            )
            if timed_out:
                wait_task.cancel()
                errors.append(TimeoutError("failed spawn did not exit within cleanup grace"))
                drain_error, drain_cancellation, drain_timed_out = (
                    await self._wait_for_protected_task(
                        wait_task,
                        deadline=deadline,
                    )
                )
                cancellation = cancellation or drain_cancellation
                if drain_timed_out:
                    errors.append(
                        TimeoutError("failed spawn wait remained pending after force-close")
                    )
                elif drain_error is not None and not isinstance(
                    drain_error, asyncio.CancelledError
                ):
                    errors.append(drain_error)
            elif wait_error is not None and not isinstance(wait_error, asyncio.CancelledError):
                errors.append(wait_error)
            if cancellation is not None:
                errors.append(cancellation)
        if errors:
            raise errors[0]

    def _force_cleanup_spawn(self, execution_token: object) -> None:
        context = self._contexts.get(execution_token)
        if context is not None:
            self._force_release_context(context)

    def _force_cleanup_process(self, process: asyncio.subprocess.Process) -> None:
        context = self._context_for_process(process)
        if context is None:
            self._force_close_process_once(process)
            return
        self._force_release_context(context)

    def _force_release_context(self, context: ProcessContext) -> None:
        if context.released:
            self._unregister_context(context)
            return
        context.released = True
        errors: list[BaseException] = []
        try:
            self._close_suspended_thread(context)
        except BaseException as error:
            errors.append(error)
        if context.assigned:
            try:
                self._terminate_job_once(context)
            except BaseException as error:
                errors.append(error)
        try:
            self._close_job(context)
        except BaseException as error:
            errors.append(error)
        if context.process is not None:
            try:
                self._force_close_process_once(context.process)
            except BaseException as error:
                errors.append(error)
        self._unregister_context(context)
        if errors:
            raise errors[0]

    def _force_close_process_once(self, process: asyncio.subprocess.Process) -> None:
        # The common runner owns the identity-based exactly-once guard. Keep
        # this wrapper so ProcessContext has one explicit process-release path.
        super()._force_cleanup_process(process)

    async def _wait_for_job_empty(self, job: _NativeHandle) -> None:
        loop = asyncio.get_running_loop()
        deadline = loop.time() + self._cleanup_grace_seconds
        while True:
            information = win32job.QueryInformationJobObject(
                job, win32job.JobObjectBasicAccountingInformation
            )
            if int(information["ActiveProcesses"]) == 0:
                return
            if loop.time() >= deadline:
                raise TimeoutError("Windows Job Object retained active processes after termination")
            await asyncio.sleep(0.01)
