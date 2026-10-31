from .rule_modules.registry import RULES

SUPPORTED_CWES = frozenset({78, 79, 89, 352, 787, 862, 918})
MAX_CWES_PER_SCAN = 4


class UnsupportedCWEError(ValueError):
    """Raised when a requested CWE has no analyzer implementation yet."""
