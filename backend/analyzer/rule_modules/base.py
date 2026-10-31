from __future__ import annotations

import ast
from dataclasses import dataclass
from typing import Callable


SinkMatcher = Callable[[str, ast.Call], tuple[int | str, ...]]


@dataclass(frozen=True)
class AnalyzerRule:
    cwe_id: int
    name: str
    source_paths: frozenset[str] = frozenset()
    sanitizer_suffixes: frozenset[str] = frozenset()
    sink_matcher: SinkMatcher | None = None

    def sink_arguments(self, called_name: str, call: ast.Call) -> tuple[int | str, ...]:
        if self.sink_matcher is None:
            return ()
        return self.sink_matcher(called_name, call)


REQUEST_SOURCES = frozenset(
    {"request.args", "request.form", "request.GET", "request.POST"}
)


def suffix(name: str) -> str:
    return name.rsplit(".", 1)[-1]


def positional_or_keyword(call: ast.Call, index: int, keyword: str) -> tuple[int | str, ...]:
    if len(call.args) > index:
        return (index,)
    if any(item.arg == keyword for item in call.keywords):
        return (keyword,)
    return ()
