from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class CustomInstructions:
    sinks: frozenset[str] = frozenset()
    tracked_variables: frozenset[str] = frozenset()

    @property
    def enabled(self) -> bool:
        return bool(self.sinks or self.tracked_variables)
