from __future__ import annotations

import ast
from typing import Iterable, Mapping, Sequence

from .custom import CustomInstructions
from .models import AnalysisResult, CustomFinding, CustomObservation, Finding, SourceObservation
from .route_checks import analyze_routes
from .rules import RULES
from .state import EMPTY as _EMPTY, Frame as _Frame, Taint as _Taint, Taints as _Taints
from .rule_modules.base import REQUEST_SOURCES


class _Analyzer:
    def __init__(
        self,
        tree: ast.Module,
        cwe_ids: tuple[int, ...],
        custom_instructions: CustomInstructions | None = None,
    ) -> None:
        self.tree = tree
        self.cwe_ids = cwe_ids
        self.custom_instructions = custom_instructions
        self.rules = tuple(RULES[cwe_id] for cwe_id in cwe_ids)
        self.module = _Frame(module_scope=True)
        self.import_aliases = self._import_aliases(tree)
        self.functions: dict[str, ast.FunctionDef | ast.AsyncFunctionDef] = {
            node.name: node
            for node in tree.body
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        }
        self.sources: dict[tuple[int, str, int], SourceObservation] = {}
        self.findings: dict[tuple[object, ...], Finding] = {}
        self.custom_findings: dict[tuple[object, ...], CustomFinding] = {}
        self.custom_observations: dict[tuple[object, ...], CustomObservation] = {}
        self.active_calls: set[str] = set()

    def run(self) -> AnalysisResult:
        self.module, _, _ = self._execute_block(self.tree.body, self.module)
        # Framework route handlers are normally invoked externally, so analyze
        # every module-level function as an entrypoint as well as resolving calls.
        for name in self.functions:
            self._call_function(name, (), {}, self.module)
        for finding in analyze_routes(self.tree, self.cwe_ids):
            key = (
                finding.cwe_id,
                finding.finding_kind,
                finding.variable_name,
                finding.location_line_number,
            )
            self.findings[key] = finding
        return AnalysisResult(
            sources=tuple(
                self.sources[key]
                for key in sorted(self.sources, key=lambda item: (item[2], item[0], item[1]))
            ),
            findings=tuple(
                self.findings[key]
                for key in sorted(
                    self.findings,
                    key=lambda item: (item[0], item[3], str(item[1]), str(item[2])),
                )
            ),
            custom_findings=tuple(
                self.custom_findings[key] for key in sorted(self.custom_findings)
            ),
            custom_observations=tuple(
                self.custom_observations[key] for key in sorted(self.custom_observations)
            ),
        )

    def _execute_block(
        self, statements: Sequence[ast.stmt], frame: _Frame
    ) -> tuple[_Frame, _Taints, bool]:
        returned: set[_Taint] = set()
        for statement in statements:
            frame, statement_returns, always_returns = self._execute_statement(statement, frame)
            returned.update(statement_returns)
            if always_returns:
                return frame, frozenset(returned), True
        return frame, frozenset(returned), False

    def _execute_statement(
        self, statement: ast.stmt, frame: _Frame
    ) -> tuple[_Frame, _Taints, bool]:
        if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            return frame, _EMPTY, False

        if isinstance(statement, ast.Assign):
            value = self._expression(statement.value, frame)
            for target in statement.targets:
                self._assign(target, value, frame)
            return frame, _EMPTY, False

        if isinstance(statement, ast.AnnAssign):
            value = self._expression(statement.value, frame) if statement.value else _EMPTY
            self._assign(statement.target, value, frame)
            return frame, _EMPTY, False

        if isinstance(statement, ast.AugAssign):
            value = self._expression(statement.target, frame) | self._expression(statement.value, frame)
            self._assign(statement.target, self._through(value, statement, ast.unparse(statement.target)), frame)
            return frame, _EMPTY, False

        if isinstance(statement, ast.Expr):
            self._expression(statement.value, frame)
            return frame, _EMPTY, False

        if isinstance(statement, ast.Return):
            value = self._expression(statement.value, frame) if statement.value else _EMPTY
            return frame, value, True

        if isinstance(statement, ast.If):
            self._expression(statement.test, frame)
            left_frame, left_returns, left_exits = self._execute_block(statement.body, frame.copy())
            right_frame, right_returns, right_exits = self._execute_block(statement.orelse, frame.copy())
            continuations = []
            if not left_exits:
                continuations.append(left_frame)
            if not right_exits:
                continuations.append(right_frame)
            joined = self._join_frames(continuations) if continuations else frame
            return joined, left_returns | right_returns, not continuations

        if isinstance(statement, (ast.For, ast.AsyncFor)):
            iterable_taints = self._expression(statement.iter, frame)
            before = frame.copy()
            body_frame = frame.copy()
            self._assign(statement.target, iterable_taints, body_frame)
            body_frame, body_returns, _ = self._execute_block(statement.body, body_frame)
            if statement.orelse:
                body_frame, else_returns, _ = self._execute_block(statement.orelse, body_frame)
                body_returns |= else_returns
            return self._join_frames((before, body_frame)), body_returns, False

        if isinstance(statement, ast.While):
            self._expression(statement.test, frame)
            before = frame.copy()
            body_frame, body_returns, _ = self._execute_block(statement.body, frame.copy())
            if statement.orelse:
                body_frame, else_returns, _ = self._execute_block(statement.orelse, body_frame)
                body_returns |= else_returns
            return self._join_frames((before, body_frame)), body_returns, False

        if isinstance(statement, (ast.With, ast.AsyncWith)):
            for item in statement.items:
                value = self._expression(item.context_expr, frame)
                if item.optional_vars:
                    self._assign(item.optional_vars, value, frame)
            return self._execute_block(statement.body, frame)

        if isinstance(statement, ast.Try):
            paths: list[_Frame] = []
            returns: set[_Taint] = set()
            body_frame, body_returns, body_exits = self._execute_block(statement.body, frame.copy())
            returns.update(body_returns)
            if not body_exits:
                if statement.orelse:
                    body_frame, else_returns, body_exits = self._execute_block(statement.orelse, body_frame)
                    returns.update(else_returns)
                if not body_exits:
                    paths.append(body_frame)
            for handler in statement.handlers:
                handler_frame = frame.copy()
                handler_frame, handler_returns, handler_exits = self._execute_block(handler.body, handler_frame)
                returns.update(handler_returns)
                if not handler_exits:
                    paths.append(handler_frame)
            joined = self._join_frames(paths) if paths else frame
            if statement.finalbody:
                joined, final_returns, final_exits = self._execute_block(statement.finalbody, joined)
                returns.update(final_returns)
                return joined, frozenset(returns), final_exits
            return joined, frozenset(returns), not paths

        if isinstance(statement, (ast.Break, ast.Continue, ast.Pass, ast.Global, ast.Nonlocal)):
            return frame, _EMPTY, False

        if isinstance(statement, ast.Delete):
            for target in statement.targets:
                if isinstance(target, ast.Name):
                    frame.locals.pop(target.id, None)
            return frame, _EMPTY, False

        # Conservatively visit expressions in less common statement forms.
        for child in ast.iter_child_nodes(statement):
            if isinstance(child, ast.expr):
                self._expression(child, frame)
        return frame, _EMPTY, False

    def _expression(self, node: ast.expr | None, frame: _Frame) -> _Taints:
        if node is None:
            return _EMPTY

        if isinstance(node, ast.Name):
            return frame.read(node.id)

        if isinstance(node, ast.Attribute):
            path = self._resolved_name(node)
            source_rules = [rule for rule in self.rules if path in rule.source_paths]
            is_custom_source = self.custom_instructions is not None and path in REQUEST_SOURCES
            if source_rules or is_custom_source:
                taints: set[_Taint] = set()
                for rule in source_rules:
                    self._record_source(rule.cwe_id, path, node.lineno)
                    taints.add(
                        _Taint(
                            cwe_id=rule.cwe_id,
                            source_expression=path,
                            source_line=node.lineno,
                            variable_name=path,
                            trace=(f"{path} (line {node.lineno})",),
                        )
                    )
                if is_custom_source:
                    taints.add(
                        _Taint(
                            cwe_id=None,
                            source_expression=path,
                            source_line=node.lineno,
                            variable_name=path,
                            trace=(f"{path} (line {node.lineno})",),
                        )
                    )
                return frozenset(
                    taints
                )
            return self._expression(node.value, frame)

        if isinstance(node, ast.Call):
            function_taints = self._expression(node.func, frame)
            positional = [self._expression(argument, frame) for argument in node.args]
            keyword_values = {
                keyword.arg: self._expression(keyword.value, frame)
                for keyword in node.keywords
                if keyword.arg is not None
            }
            called_name = self._resolved_name(node.func)
            suffix = called_name.rsplit(".", 1)[-1]
            if (
                self.custom_instructions is not None
                and called_name in self.custom_instructions.sinks
            ):
                arguments = frozenset().union(*positional, *keyword_values.values())
                self._record_custom_sink(
                    called_name,
                    node,
                    frozenset(taint for taint in arguments if taint.cwe_id is None),
                )
            for rule in self.rules:
                for argument in rule.sink_arguments(called_name, node):
                    if isinstance(argument, int):
                        value = positional[argument] if len(positional) > argument else _EMPTY
                    else:
                        value = keyword_values.get(argument, _EMPTY)
                    self._record_sink(
                        rule.cwe_id,
                        node,
                        called_name,
                        frozenset(taint for taint in value if taint.cwe_id == rule.cwe_id),
                    )

            if isinstance(node.func, ast.Name) and node.func.id in self.functions:
                return self._call_function(node.func.id, positional, keyword_values, frame)

            # Calls such as request.args.get(...) retain taint from the source
            # attribute. Other call results conservatively inherit argument taint.
            result_taints = function_taints | frozenset().union(*positional, *keyword_values.values())
            sanitized_cwes = {
                rule.cwe_id for rule in self.rules if suffix in rule.sanitizer_suffixes
            }
            return frozenset(taint for taint in result_taints if taint.cwe_id not in sanitized_cwes)

        if isinstance(node, ast.Subscript):
            return self._expression(node.value, frame) | self._expression(node.slice, frame)

        if isinstance(node, ast.BinOp):
            values = self._expression(node.left, frame) | self._expression(node.right, frame)
            return self._through(values, node, ast.unparse(node))

        if isinstance(node, ast.JoinedStr):
            values = frozenset().union(*(self._expression(value, frame) for value in node.values))
            return self._through(values, node, ast.unparse(node))

        if isinstance(node, ast.FormattedValue):
            return self._expression(node.value, frame)

        if isinstance(node, ast.IfExp):
            self._expression(node.test, frame)
            return self._expression(node.body, frame) | self._expression(node.orelse, frame)

        if isinstance(node, ast.NamedExpr):
            value = self._expression(node.value, frame)
            self._assign(node.target, value, frame)
            return value

        values: set[_Taint] = set()
        for child in ast.iter_child_nodes(node):
            if isinstance(child, ast.expr):
                values.update(self._expression(child, frame))
        return frozenset(values)

    def _assign(self, target: ast.expr, value: _Taints, frame: _Frame) -> None:
        if isinstance(target, ast.Name):
            propagated = self._through(value, target, target.id, variable_name=target.id)
            frame.locals[target.id] = propagated
            if (
                self.custom_instructions is not None
                and target.id in self.custom_instructions.tracked_variables
            ):
                self._record_custom_observations(target.id, target, propagated)
        elif isinstance(target, (ast.Tuple, ast.List)):
            for item in target.elts:
                self._assign(item, value, frame)
        elif isinstance(target, ast.Starred):
            self._assign(target.value, value, frame)
        elif isinstance(target, (ast.Attribute, ast.Subscript)):
            self._expression(target, frame)

    def _call_function(
        self,
        name: str,
        positional: Sequence[_Taints],
        keywords: Mapping[str, _Taints],
        caller_frame: _Frame,
    ) -> _Taints:
        function = self.functions[name]
        arguments = list(function.args.posonlyargs) + list(function.args.args)
        local_names = self._function_local_names(function)
        local_values: dict[str, _Taints] = {}
        for index, argument in enumerate(arguments):
            if index < len(positional):
                local_values[argument.arg] = self._through(
                    positional[index], function, argument.arg, variable_name=argument.arg
                )
            elif argument.arg in keywords:
                local_values[argument.arg] = self._through(
                    keywords[argument.arg], function, argument.arg, variable_name=argument.arg
                )
            else:
                local_values[argument.arg] = _EMPTY
        for argument in function.args.kwonlyargs:
            local_values[argument.arg] = self._through(
                keywords.get(argument.arg, _EMPTY), function, argument.arg, variable_name=argument.arg
            )
        if self.custom_instructions is not None:
            for argument in arguments + list(function.args.kwonlyargs):
                if argument.arg in self.custom_instructions.tracked_variables:
                    self._record_custom_observations(
                        argument.arg, argument, local_values.get(argument.arg, _EMPTY)
                    )

        if name in self.active_calls:
            # A recursive edge returns its tainted inputs conservatively. The
            # active frame still analyzes the function body and any sinks in it.
            return frozenset().union(*local_values.values()) if local_values else _EMPTY

        self.active_calls.add(name)
        try:
            global_values = caller_frame.locals if caller_frame.module_scope else caller_frame.globals
            frame = _Frame(local_values, local_names, global_values)
            _, returned, _ = self._execute_block(function.body, frame)
            return returned
        finally:
            self.active_calls.remove(name)

    def _record_source(self, cwe_id: int, expression: str, line: int) -> None:
        self.sources[(cwe_id, expression, line)] = SourceObservation(cwe_id, expression, line)

    def _record_sink(
        self, cwe_id: int, node: ast.Call, expression: str, taints: _Taints
    ) -> None:
        for taint in taints:
            variable = taint.variable_name or taint.source_expression
            trace = taint.trace + (f"{expression} (line {node.lineno})",)
            finding = Finding(
                cwe_id=cwe_id,
                variable_name=variable,
                source_expression=taint.source_expression,
                source_line_number=taint.source_line,
                sink_expression=expression,
                sink_line_number=node.lineno,
                trace=trace,
                location_line_number=node.lineno,
            )
            key = (
                finding.cwe_id,
                finding.finding_kind,
                finding.source_expression,
                finding.source_line_number,
                finding.sink_expression,
                finding.sink_line_number,
                finding.variable_name,
            )
            self.findings[key] = finding

    def _record_custom_sink(
        self, expression: str, node: ast.Call, taints: _Taints
    ) -> None:
        for taint in taints:
            finding = CustomFinding(
                rule_name=expression,
                variable_name=taint.variable_name or taint.source_expression,
                source_expression=taint.source_expression,
                source_line_number=taint.source_line,
                sink_expression=expression,
                sink_line_number=node.lineno,
                trace=taint.trace + (f"{expression} (line {node.lineno})",),
            )
            key = (
                finding.rule_name,
                finding.source_expression,
                finding.source_line_number,
                finding.sink_line_number,
                finding.variable_name,
            )
            self.custom_findings[key] = finding

    def _record_custom_observations(
        self, variable_name: str, node: ast.AST, taints: _Taints
    ) -> None:
        for taint in taints:
            if taint.cwe_id is not None:
                continue
            observation = CustomObservation(
                variable_name=variable_name,
                source_expression=taint.source_expression,
                source_line_number=taint.source_line,
                line_number=getattr(node, "lineno", 0),
                trace=taint.trace,
            )
            line = getattr(node, "lineno", 0)
            key = (variable_name, taint.source_expression, taint.source_line, line)
            self.custom_observations[key] = observation

    @staticmethod
    def _through(
        taints: Iterable[_Taint],
        node: ast.AST,
        label: str,
        *,
        variable_name: str | None = None,
    ) -> _Taints:
        line = getattr(node, "lineno", 0)
        return frozenset(
            taint.through(label, line, variable_name=variable_name) for taint in taints
        )

    def _resolved_name(self, node: ast.AST) -> str:
        if isinstance(node, ast.Name):
            name = self.import_aliases.get(node.id, node.id)
            return name.removeprefix("flask.") if name.startswith("flask.request") else name
        if isinstance(node, ast.Attribute):
            base = self._resolved_name(node.value)
            name = f"{base}.{node.attr}" if base else node.attr
            return name.removeprefix("flask.") if name.startswith("flask.request") else name
        return ast.unparse(node)

    @staticmethod
    def _import_aliases(tree: ast.Module) -> dict[str, str]:
        aliases: dict[str, str] = {}
        for node in tree.body:
            if isinstance(node, ast.Import):
                for item in node.names:
                    local_name = item.asname or item.name.split(".", 1)[0]
                    aliases[local_name] = item.name if item.asname else local_name
            elif isinstance(node, ast.ImportFrom) and node.module:
                for item in node.names:
                    if item.name != "*":
                        aliases[item.asname or item.name] = f"{node.module}.{item.name}"
        return aliases

    @staticmethod
    def _join_frames(frames: Iterable[_Frame]) -> _Frame:
        frames = tuple(frames)
        if not frames:
            return _Frame()
        names = set().union(*(frame.locals.keys() for frame in frames))
        local_names = set().union(*(frame.local_names for frame in frames))
        globals_map = frames[0].globals
        joined = _Frame(local_names=local_names, globals=globals_map, module_scope=frames[0].module_scope)
        for name in names:
            joined.locals[name] = frozenset().union(
                *(frame.locals.get(name, _EMPTY) for frame in frames)
            )
        return joined

    @staticmethod
    def _function_local_names(
        function: ast.FunctionDef | ast.AsyncFunctionDef,
    ) -> set[str]:
        names = {argument.arg for argument in function.args.posonlyargs}
        names.update(argument.arg for argument in function.args.args)
        names.update(argument.arg for argument in function.args.kwonlyargs)
        if function.args.vararg:
            names.add(function.args.vararg.arg)
        if function.args.kwarg:
            names.add(function.args.kwarg.arg)

        class LocalNameVisitor(ast.NodeVisitor):
            def visit_Name(self, node: ast.Name) -> None:
                if isinstance(node.ctx, (ast.Store, ast.Param)):
                    names.add(node.id)

            def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
                if node is function:
                    for child in node.body:
                        self.visit(child)
                else:
                    names.add(node.name)
                    





                names.add(node.name)

        LocalNameVisitor().visit(function)
        return names
