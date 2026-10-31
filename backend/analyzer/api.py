from __future__ import annotations

import ast
from typing import Sequence

from .engine import _Analyzer
from .models import AnalysisResult
from .custom import CustomInstructions
from .rules import MAX_CWES_PER_SCAN, SUPPORTED_CWES, UnsupportedCWEError


def analyze(
    source_code: str,
    cwe_ids: Sequence[int] | None = None,
    custom_instructions: CustomInstructions | None = None,
) -> AnalysisResult:
    """Analyze one Python module and return discovered request sources/findings.

    ``SyntaxError`` is raised for invalid Python. ``UnsupportedCWEError`` is
    raised when a selected CWE has no implemented rules. CWE-89 is selected by
    default; callers may pass up to four distinct CWE IDs as the future API will.
    """
    if not isinstance(source_code, str):
        raise TypeError("source_code must be a string")

    selected = _validate_cwes(cwe_ids)
    tree = ast.parse(source_code)
    return _Analyzer(tree, selected, custom_instructions).run()


def _validate_cwes(cwe_ids: Sequence[int] | None) -> tuple[int, ...]:
    requested = (89,) if cwe_ids is None else tuple(cwe_ids)
    if not requested:
        raise ValueError("select at least one CWE")
    if any(not isinstance(cwe_id, int) or isinstance(cwe_id, bool) for cwe_id in requested):
        raise TypeError("CWE IDs must be integers")

    unique = tuple(dict.fromkeys(requested))
    if len(unique) > MAX_CWES_PER_SCAN:
        raise ValueError(f"at most {MAX_CWES_PER_SCAN} CWEs may be selected")
    unsupported = sorted(set(unique) - SUPPORTED_CWES)
    if unsupported:
        values = ", ".join(f"CWE-{cwe_id}" for cwe_id in unsupported)
        raise UnsupportedCWEError(f"no analyzer rules are implemented for {values}")
    return unique
