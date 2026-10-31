from __future__ import annotations

import ast

from .base import AnalyzerRule, REQUEST_SOURCES, positional_or_keyword, suffix


def _command_arguments(name: str, call: ast.Call) -> tuple[int | str, ...]:
    short = suffix(name)
    if name in {"os.system", "os.popen", "system", "popen"}:
        return positional_or_keyword(call, 0, "command")
    if name.startswith("subprocess.") and short in {
        "run", "Popen", "call", "check_call", "check_output"
    }:
        shell_enabled = any(
            item.arg == "shell" and isinstance(item.value, ast.Constant) and item.value.value is True
            for item in call.keywords
        )
        if shell_enabled:
            return positional_or_keyword(call, 0, "args")
    return ()


RULE = AnalyzerRule(
    cwe_id=78,
    name="OS command injection",
    source_paths=REQUEST_SOURCES,
    sink_matcher=_command_arguments,
)
