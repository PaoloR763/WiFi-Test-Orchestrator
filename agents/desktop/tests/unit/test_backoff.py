from __future__ import annotations

from wto_desktop_agent.infrastructure.backoff import BackoffPolicy


class MidpointRandom:
    def uniform(self, lower: float, upper: float) -> float:
        return (lower + upper) / 2


def test_exponential_backoff_is_bounded_and_jitter_is_deterministic() -> None:
    policy = BackoffPolicy(1.0, 10.0, 2.0, 0.25)
    random = MidpointRandom()
    assert [policy.delay(attempt, random) for attempt in range(6)] == [
        1,
        2,
        4,
        8,
        10,
        10,
    ]
