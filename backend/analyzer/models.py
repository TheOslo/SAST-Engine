from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class SourceObservation:
    cwe_id: int
    expression: str
    line_number: int

    def to_dict(self) -> dict[str, object]:
        return {
            "cwe_id": self.cwe_id,
            "expression": self.expression,
            "line_number": self.line_number,
        }


@dataclass(frozen=True)
class SanitizedFlow:
    cwe_id: int
    source_expression: str
    source_line_number: int
    sanitizer_expression: str
    sanitizer_line_number: int
    trace: tuple[str, ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "cwe_id": self.cwe_id,
            "source_expression": self.source_expression,
            "source_line_number": self.source_line_number,
            "sanitizer_expression": self.sanitizer_expression,
            "sanitizer_line_number": self.sanitizer_line_number,
            "trace": list(self.trace),
        }


@dataclass(frozen=True)
class Finding:
    cwe_id: int
    variable_name: str
    source_expression: str | None
    source_line_number: int | None
    sink_expression: str | None
    sink_line_number: int | None
    trace: tuple[str, ...]
    finding_kind: str = "taint"
    evidence: tuple[str, ...] = ()
    location_line_number: int | None = None

    def to_dict(self) -> dict[str, object]:
        return {
            "cwe_id": self.cwe_id,
            "variable_name": self.variable_name,
            "source_expression": self.source_expression,
            "source_line_number": self.source_line_number,
            "sink_expression": self.sink_expression,
            "sink_line_number": self.sink_line_number,
            "trace": list(self.trace),
            "finding_kind": self.finding_kind,
            "evidence": list(self.evidence),
            "location_line_number": self.location_line_number,
        }


@dataclass(frozen=True)
class CustomFinding:
    rule_name: str
    variable_name: str
    source_expression: str
    source_line_number: int
    sink_expression: str
    sink_line_number: int
    trace: tuple[str, ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "rule_name": self.rule_name,
            "variable_name": self.variable_name,
            "source_expression": self.source_expression,
            "source_line_number": self.source_line_number,
            "sink_expression": self.sink_expression,
            "sink_line_number": self.sink_line_number,
            "trace": list(self.trace),
        }


@dataclass(frozen=True)
class CustomObservation:
    variable_name: str
    source_expression: str
    source_line_number: int
    line_number: int
    trace: tuple[str, ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "variable_name": self.variable_name,
            "source_expression": self.source_expression,
            "source_line_number": self.source_line_number,
            "line_number": self.line_number,
            "trace": list(self.trace),
        }


@dataclass(frozen=True)
class AnalysisResult:
    sources: tuple[SourceObservation, ...]
    findings: tuple[Finding, ...]
    custom_findings: tuple[CustomFinding, ...] = ()
    custom_observations: tuple[CustomObservation, ...] = ()
    sanitized_flows: tuple[SanitizedFlow, ...] = ()

    def to_dict(self) -> dict[str, object]:
        return {
            "sources": [source.to_dict() for source in self.sources],
            "findings": [finding.to_dict() for finding in self.findings],
            "custom_findings": [item.to_dict() for item in self.custom_findings],
            "custom_observations": [item.to_dict() for item in self.custom_observations],
            "sanitized_flows": [item.to_dict() for item in self.sanitized_flows],
        }
