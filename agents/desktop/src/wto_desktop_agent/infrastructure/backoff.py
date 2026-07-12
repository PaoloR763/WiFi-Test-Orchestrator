from __future__ import annotations

from dataclasses import dataclass

from wto_desktop_agent.ports.time import RandomSource


@dataclass(frozen=True)
class BackoffPolicy:
    initial_seconds: float
    maximum_seconds: float
    multiplier: float
    jitter_ratio: float

    def delay(self, attempt: int, random_source: RandomSource) -> float:
        base = min(self.maximum_seconds, self.initial_seconds * self.multiplier**attempt)
        jitter = base * self.jitter_ratio
        return max(0.0, random_source.uniform(base - jitter, base + jitter))
