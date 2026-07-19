from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
from tempfile import TemporaryDirectory
from uuid import uuid4

from hypothesis import HealthCheck, settings
from hypothesis.stateful import RuleBasedStateMachine, invariant, rule

from wto_desktop_agent.domain.models import LocalTaskEnvelope
from wto_desktop_agent.infrastructure.sqlite.store import SQLiteStore


class PersistentTaskMachine(RuleBasedStateMachine):
    def __init__(self) -> None:
        super().__init__()
        self.temp = TemporaryDirectory()
        self.store = SQLiteStore(Path(self.temp.name) / "agent.sqlite3")
        self.store.initialize()
        now = datetime.now(UTC)
        self.task = LocalTaskEnvelope(
            task_id=uuid4(),
            execution_id=uuid4(),
            task_type="protocol.contract_check",
            task_type_version="1.0.0",
            issued_at=now,
            not_before=now,
            expires_at=now + timedelta(minutes=5),
            idempotency_key=uuid4(),
            required_capabilities=["network.http.probe"],
            foreground_requirement="not_required",
            user_interaction_requirement="none",
        )

    @rule()
    def deliver(self) -> None:
        self.store.ingest_task(self.task)

    @rule()
    def claim(self) -> None:
        self.store.claim_task(str(self.task.task_id))

    @rule()
    def crash(self) -> None:
        self.store.recover_interrupted()

    @invariant()
    def one_effect_and_one_claim(self) -> None:
        assert len(self.store.rows("idempotency_effects")) <= 1
        assert len(self.store.rows("task_attempts")) <= 1

    def teardown(self) -> None:
        self.temp.cleanup()


TestPersistentTaskMachine = PersistentTaskMachine.TestCase
TestPersistentTaskMachine.settings = settings(
    database=None,
    deadline=None,
    max_examples=20,
    stateful_step_count=10,
    suppress_health_check=[HealthCheck.too_slow],
)
