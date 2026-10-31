from .base import AnalyzerRule, REQUEST_SOURCES, positional_or_keyword, suffix


def _sql_arguments(name, call):
    if suffix(name) not in {"execute", "raw"}:
        return ()
    if call.args:
        return (0,)
    for keyword in ("sql", "operation"):
        if any(item.arg == keyword for item in call.keywords):
            return (keyword,)
    return ()


RULE = AnalyzerRule(
    cwe_id=89,
    name="SQL injection",
    source_paths=REQUEST_SOURCES,
    sink_matcher=_sql_arguments,
)
