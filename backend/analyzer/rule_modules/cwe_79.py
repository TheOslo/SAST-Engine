from .base import AnalyzerRule, REQUEST_SOURCES, positional_or_keyword, suffix


def _template_arguments(name, call):
    short = suffix(name)
    if short == "render_template_string":
        return positional_or_keyword(call, 0, "source")
    if short == "mark_safe":
        return positional_or_keyword(call, 0, "s")
    return ()


RULE = AnalyzerRule(
    cwe_id=79,
    name="Cross-site scripting",
    source_paths=REQUEST_SOURCES,
    sanitizer_suffixes=frozenset({"escape", "conditional_escape"}),
    sink_matcher=_template_arguments,
)
