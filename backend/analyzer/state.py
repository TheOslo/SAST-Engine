from __future__ import annotations

from dataclasses import dataclass, field
from typing import Mapping


@dataclass(frozen=True)
class Taint:
    cwe_id: int | None
    source_expression: str
    source_line: int
    variable_name: str
    trace: tuple[str, ...]

    def through(self, label: str, line: int, *, variable_name: str | None = None) -> Taint:
        step = f"{label} (line {line})"
        trace = self.trace if self.trace and self.trace[-1] == step else self.trace + (step,)
        # Bound trace size so loop-heavy input cannot grow provenance without limit.
        if len(trace) > 40:
            trace = trace[:20] + ("...",) + trace[-19:]
        return Taint(
            cwe_id=self.cwe_id,
            source_expression=self.source_expression,
            source_line=self.source_line,
            variable_name=variable_name or self.variable_name,
            trace=trace,
        )


Taints = frozenset[Taint]
EMPTY: Taints = frozenset()


@dataclass
class Frame:
    locals: dict[str, Taints] = field(default_factory=dict)
    local_names: set[str] = field(default_factory=set)
    globals: Mapping[str, Taints] = field(default_factory=dict)
    module_scope: bool = False

    def copy(self) -> Frame:
        return Frame(dict(self.locals), set(self.local_names), self.globals, self.module_scope)

    def read(self, name: str) -> Taints:
        if name in self.locals:
            return self.locals[name]
        if name in self.local_names:
            return EMPTY
        return self.globals.get(name, EMPTY)
