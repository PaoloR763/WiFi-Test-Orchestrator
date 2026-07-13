from __future__ import annotations

import asyncio

import win32api
import win32con
import win32job

from wto_desktop_agent.platforms.common import AllowlistedProcessRunner, CommandSpec


class WindowsProcessRunner(AllowlistedProcessRunner):
    def __init__(self, commands: dict[str, CommandSpec] | None = None) -> None:
        super().__init__(commands or {})
        self._jobs: dict[int, object] = {}

    async def start_process(
        self, spec: CommandSpec, argv: list[str], environment: dict[str, str]
    ) -> asyncio.subprocess.Process:
        return await asyncio.create_subprocess_exec(
            str(spec.executable),
            *argv,
            cwd=spec.cwd,
            env=environment,
            stdin=asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            creationflags=win32con.CREATE_NEW_PROCESS_GROUP,
        )

    def after_start(self, process: asyncio.subprocess.Process) -> None:
        self.assign_job(process.pid)

    async def terminate(self, process: asyncio.subprocess.Process) -> None:
        job = self._jobs.pop(process.pid, None)
        if job is not None:
            win32job.TerminateJobObject(job, 1)
        else:
            process.kill()
        await process.wait()

    def assign_job(self, process_id: int) -> None:
        job = win32job.CreateJobObject(None, "")
        information = win32job.QueryInformationJobObject(
            job, win32job.JobObjectExtendedLimitInformation
        )
        information["BasicLimitInformation"][
            "LimitFlags"
        ] |= win32job.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        win32job.SetInformationJobObject(
            job, win32job.JobObjectExtendedLimitInformation, information
        )
        handle = win32api.OpenProcess(
            win32con.PROCESS_TERMINATE | win32con.PROCESS_SET_QUOTA, False, process_id
        )
        try:
            win32job.AssignProcessToJobObject(job, handle)
        finally:
            handle.Close()
        self._jobs[process_id] = job
