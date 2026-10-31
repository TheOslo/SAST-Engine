from .base import AnalyzerRule

AUTH_GUARDS = frozenset(
    {
        "login_required",
        "permission_required",
        "user_passes_test",
        "requires_auth",
        "jwt_required",
        "authenticated",
        "is_authenticated",
        "has_perm",
        "has_perms",
        "check_permission",
        "is_authorized",
    }
)

RULE = AnalyzerRule(cwe_id=862, name="Missing authorization")
