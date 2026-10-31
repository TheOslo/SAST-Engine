from .base import AnalyzerRule

CSRF_GUARDS = frozenset({"csrf_protect", "csrf_protected", "csrf_required"})
CSRF_EXEMPTIONS = frozenset({"csrf_exempt"})
CSRF_MIDDLEWARE_NAMES = frozenset({"MIDDLEWARE", "MIDDLEWARE_CLASSES"})

RULE = AnalyzerRule(cwe_id=352, name="Cross-site request forgery")
