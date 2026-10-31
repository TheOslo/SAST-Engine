from __future__ import annotations

import ast

from .models import Finding
from .rule_modules.cwe_352 import CSRF_EXEMPTIONS, CSRF_GUARDS, CSRF_MIDDLEWARE_NAMES
from .rule_modules.cwe_862 import AUTH_GUARDS


_MUTATING_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})
def analyze_routes(tree: ast.Module, cwe_ids: tuple[int, ...]) -> tuple[Finding, ...]:
    findings: list[Finding] = []
    aliases = _import_aliases(tree)
    module_csrf = _module_has_csrf_protection(tree, aliases)
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        methods, route_line = _route_methods(node, aliases)
        if not methods.intersection(_MUTATING_METHODS):
            continue
        decorator_names = {_resolved_name(item, aliases).rsplit(".", 1)[-1] for item in node.decorator_list}
        body_names = _body_security_names(node, aliases)

        if 352 in cwe_ids:
            exempt = bool(decorator_names & CSRF_EXEMPTIONS)
            protected = module_csrf or bool(decorator_names & CSRF_GUARDS)
            if exempt or not protected:
                reason = (
                    "route is explicitly marked csrf_exempt"
                    if exempt
                    else "no recognized CSRF protection is visible in this module or route"
                )
                findings.append(_route_finding(352, node, route_line, reason))

        if 862 in cwe_ids:
            guarded = bool(decorator_names & AUTH_GUARDS) or bool(body_names & AUTH_GUARDS)
            if not guarded:
                findings.append(
                    _route_finding(
                        862,
                        node,
                        route_line,
                        "state-changing route has no recognized authentication or permission guard",
                    )
                )
    return tuple(findings)


def _route_methods(
    function: ast.FunctionDef | ast.AsyncFunctionDef, aliases: dict[str, str]
) -> tuple[set[str], int]:
    methods: set[str] = set()
    route_line = function.lineno
    found_route = False
    for decorator in function.decorator_list:
        name = _resolved_name(decorator, aliases).rsplit(".", 1)[-1]
        if name in {"post", "put", "patch", "delete"}:
            methods.add(name.upper())
            found_route = True
            route_line = min(route_line, getattr(decorator, "lineno", function.lineno))
        elif name in {"require_POST", "require_PUT", "require_http_methods", "api_view"}:
            found_route = True
            route_line = min(route_line, getattr(decorator, "lineno", function.lineno))
            if name == "require_POST":
                methods.add("POST")
            elif name == "require_PUT":
                methods.add("PUT")
            else:
                methods.update(_literal_methods(decorator))
        elif name == "route":
            found_route = True
            route_line = min(route_line, getattr(decorator, "lineno", function.lineno))
            methods.update(_literal_methods(decorator))
    return (methods if found_route else set()), route_line


def _literal_methods(node: ast.AST) -> set[str]:
    methods: set[str] = set()
    for child in ast.walk(node):
        if isinstance(child, ast.keyword) and child.arg in {"methods", "http_method_names"}:
            values = child.value.elts if isinstance(child.value, (ast.List, ast.Tuple, ast.Set)) else ()
            methods.update(
                value.value.upper()
                for value in values
                if isinstance(value, ast.Constant) and isinstance(value.value, str)
            )
        if isinstance(child, ast.List) and any(
            isinstance(item, ast.Constant) and item.value in {"GET", "POST", "PUT", "PATCH", "DELETE"}
            for item in child.elts
        ):
            methods.update(
                item.value.upper()
                for item in child.elts
                if isinstance(item, ast.Constant) and isinstance(item.value, str)
            )
    return methods


def _module_has_csrf_protection(tree: ast.Module, aliases: dict[str, str]) -> bool:
    for statement in tree.body:
        value: ast.expr | None = None
        if isinstance(statement, ast.Expr):
            value = statement.value
        elif isinstance(statement, ast.Assign):
            value = statement.value
        elif isinstance(statement, ast.AnnAssign):
            value = statement.value
        if isinstance(value, ast.Call) and _resolved_name(value.func, aliases).rsplit(".", 1)[-1] == "CSRFProtect":
            return True

        if isinstance(statement, (ast.Assign, ast.AnnAssign)):
            targets = statement.targets if isinstance(statement, ast.Assign) else [statement.target]
            names = {target.id for target in targets if isinstance(target, ast.Name)}
            if names.intersection(CSRF_MIDDLEWARE_NAMES) and value is not None and any(
                isinstance(item, ast.Constant)
                and isinstance(item.value, str)
                and "CsrfViewMiddleware" in item.value
                for item in ast.walk(value)
            ):
                return True
    return False


def _body_security_names(
    function: ast.FunctionDef | ast.AsyncFunctionDef, aliases: dict[str, str]
) -> set[str]:
    names: set[str] = set()
    security_attributes = {
        "is_authenticated", "has_perm", "has_perms", "check_permission", "is_authorized"
    }
    for node in ast.walk(function):
        if isinstance(node, ast.Attribute) and node.attr in security_attributes:
            names.add(node.attr)
        elif isinstance(node, ast.Call):
            name = _resolved_name(node.func, aliases).rsplit(".", 1)[-1]
            if name in AUTH_GUARDS:
                names.add(name)
    return names


def _import_aliases(tree: ast.Module) -> dict[str, str]:
    aliases: dict[str, str] = {}
    for node in tree.body:
        if isinstance(node, ast.Import):
            for item in node.names:
                local = item.asname or item.name.split(".", 1)[0]
                aliases[local] = item.name if item.asname else local
        elif isinstance(node, ast.ImportFrom) and node.module:
            for item in node.names:
                if item.name != "*":
                    aliases[item.asname or item.name] = f"{node.module}.{item.name}"
    return aliases


def _resolved_name(node: ast.AST, aliases: dict[str, str]) -> str:
    if isinstance(node, ast.Call):
        return _resolved_name(node.func, aliases)
    if isinstance(node, ast.Name):
        return aliases.get(node.id, node.id)
    if isinstance(node, ast.Attribute):
        base = _resolved_name(node.value, aliases)
        return f"{base}.{node.attr}" if base else node.attr
    return ""


def _route_finding(
    cwe_id: int,
    function: ast.FunctionDef | ast.AsyncFunctionDef,
    route_line: int,
    reason: str,
) -> Finding:
    evidence = (reason, f"state-changing route: {function.name}")
    return Finding(
        cwe_id=cwe_id,
        variable_name=function.name,
        source_expression=None,
        source_line_number=None,
        sink_expression=None,
        sink_line_number=None,
        trace=(f"{reason} (line {route_line})",),
        finding_kind="route_heuristic",
        evidence=evidence,
        location_line_number=route_line,
    )
