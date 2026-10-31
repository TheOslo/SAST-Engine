from .base import AnalyzerRule, REQUEST_SOURCES, suffix


def _buffer_arguments(name, call):
    if suffix(name) not in {"memmove", "memset"}:
        return ()
    # ctypes.memmove(dst, src, count) and ctypes.memset(dst, value, count).
    return (0, 2)


RULE = AnalyzerRule(
    cwe_id=787,
    name="Out-of-bounds write to low-level buffer",
    source_paths=REQUEST_SOURCES,
    sink_matcher=_buffer_arguments,
)
