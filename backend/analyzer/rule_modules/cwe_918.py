from .base import AnalyzerRule, REQUEST_SOURCES, suffix


_HTTP_METHODS = frozenset({"get", "post", "put", "patch", "delete", "head", "options"})


def _url_arguments(name, call):
    short = suffix(name)
    if name == "urllib.request.urlopen" or short == "urlopen":
        return (0,) if call.args else (("url",) if any(k.arg == "url" for k in call.keywords) else ())
    if name.startswith(("requests.", "httpx.")):
        if short == "request":
            return (1,) if len(call.args) > 1 else (("url",) if any(k.arg == "url" for k in call.keywords) else ())
        if short in _HTTP_METHODS:
            return (0,) if call.args else (("url",) if any(k.arg == "url" for k in call.keywords) else ())
    return ()


RULE = AnalyzerRule(
    cwe_id=918,
    name="Server-side request forgery",
    source_paths=REQUEST_SOURCES,
    sink_matcher=_url_arguments,
)
