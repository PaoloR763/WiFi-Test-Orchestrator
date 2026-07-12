from __future__ import annotations

from enum import StrEnum


class TaskState(StrEnum):
    RECEIVED = "received"
    DUPLICATE = "duplicate"
    SKIPPED = "skipped"
    BLOCKED = "blocked"
    REJECTED = "rejected"
    QUEUED = "queued"
    PREPARING = "preparing"
    RUNNING = "running"
    CANCEL_REQUESTED = "cancel_requested"
    CLEANING_UP = "cleaning_up"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    INTERRUPTED = "interrupted"


PRE_EXECUTION_TERMINAL = {
    TaskState.DUPLICATE,
    TaskState.SKIPPED,
    TaskState.BLOCKED,
    TaskState.REJECTED,
}
EXECUTION_TERMINAL = {
    TaskState.COMPLETED,
    TaskState.FAILED,
    TaskState.CANCELLED,
    TaskState.INTERRUPTED,
}
TERMINAL_STATES = PRE_EXECUTION_TERMINAL | EXECUTION_TERMINAL

ALLOWED_TRANSITIONS: dict[TaskState, set[TaskState]] = {
    TaskState.RECEIVED: {
        TaskState.DUPLICATE,
        TaskState.SKIPPED,
        TaskState.BLOCKED,
        TaskState.REJECTED,
        TaskState.QUEUED,
    },
    TaskState.QUEUED: {
        TaskState.PREPARING,
        TaskState.CANCEL_REQUESTED,
        TaskState.SKIPPED,
        TaskState.BLOCKED,
        TaskState.REJECTED,
    },
    TaskState.PREPARING: {
        TaskState.RUNNING,
        TaskState.CANCEL_REQUESTED,
        TaskState.FAILED,
        TaskState.INTERRUPTED,
    },
    TaskState.RUNNING: {
        TaskState.CANCEL_REQUESTED,
        TaskState.CLEANING_UP,
        TaskState.INTERRUPTED,
    },
    TaskState.CANCEL_REQUESTED: {TaskState.CLEANING_UP},
    TaskState.CLEANING_UP: {
        TaskState.COMPLETED,
        TaskState.FAILED,
        TaskState.CANCELLED,
        TaskState.INTERRUPTED,
    },
}


def ensure_transition(current: TaskState, target: TaskState) -> None:
    if target not in ALLOWED_TRANSITIONS.get(current, set()):
        raise ValueError(f"invalid task transition: {current} -> {target}")
