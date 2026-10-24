"""Output renderers: human text, JSON, and SARIF 2.1.0 for code-scanning UIs."""

from __future__ import annotations

import json
from collections import Counter
from typing import Any

from squatwatch import __version__
from squatwatch.models import Finding, ScanResult, Severity
from squatwatch.rules import RULES

JSON_SCHEMA_VERSION = 1

_SARIF_LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}


def _finding_dict(f: Finding) -> dict[str, Any]:
    out: dict[str, Any] = {
        "rule": f.rule,
        "severity": f.severity.label,
        "title": f.title,
        "message": f.message,
    }
    if f.location is not None:
        out["location"] = {"path": f.location.path, "line": f.location.line}
    if f.package is not None:
        out["package"] = f.package
    if f.ecosystem is not None:
        out["ecosystem"] = f.ecosystem.value
    if f.score is not None:
        out["score"] = f.score
    if f.evidence:
        out["evidence"] = dict(f.evidence)
    return out


def render_json(result: ScanResult, *, fail_on: Severity) -> str:
    """Stable machine-readable report."""
    findings = result.sorted_findings()
    counts = Counter(f.severity.label for f in findings)
    doc = {
        "schema": JSON_SCHEMA_VERSION,
        "tool": {"name": "squatwatch", "version": __version__},
        "summary": {
            "files": len(result.files),
            "dependencies": len(result.dependencies),
            "findings": len(findings),
            "by_severity": {s.label: counts.get(s.label, 0) for s in reversed(Severity)},
            "fail_on": fail_on.label,
            "errors": len(result.errors),
        },
        "findings": [_finding_dict(f) for f in findings],
        "errors": list(result.errors),
    }
    return json.dumps(doc, indent=2, sort_keys=False, default=str) + "\n"


def render_text(result: ScanResult, *, fail_on: Severity, verbose: bool = False) -> str:
    """Human-readable report grouped by severity."""
    findings = result.sorted_findings()
    lines: list[str] = []
    for f in findings:
        where = str(f.location) if f.location else "-"
        score = f" score={f.score:.2f}" if f.score is not None else ""
        lines.append(f"{f.severity.label.upper():8} {f.rule}  {where}{score}")
        lines.append(f"         {f.title}")
        lines.append(f"         {f.message}")
        if verbose and f.evidence:
            lines.append(f"         evidence: {json.dumps(dict(f.evidence), default=str)}")
    if result.errors:
        lines.append("")
        lines.append("errors:")
        lines.extend(f"  {e}" for e in result.errors)
    counts = Counter(f.severity for f in findings)
    gating = sum(n for sev, n in counts.items() if sev >= fail_on)
    summary = ", ".join(f"{counts[s]} {s.label}" for s in reversed(Severity) if counts[s]) or "none"
    lines.append("")
    lines.append(
        f"scanned {len(result.files)} file(s), {len(result.dependencies)} dependency entries; "
        f"findings: {summary}; {gating} at or above fail-on={fail_on.label}"
    )
    return "\n".join(lines) + "\n"


def render_sarif(result: ScanResult) -> str:
    """SARIF 2.1.0 log with one run."""
    findings = result.sorted_findings()
    used = sorted({f.rule for f in findings})
    rules = [
        {
            "id": rid,
            "name": RULES[rid].name,
            "shortDescription": {"text": RULES[rid].summary},
        }
        for rid in used
        if rid in RULES
    ]
    results = []
    for f in findings:
        entry: dict[str, Any] = {
            "ruleId": f.rule,
            "level": _SARIF_LEVEL[f.severity],
            "message": {"text": f"{f.title}: {f.message}"},
            "properties": {"severity": f.severity.label},
        }
        if f.score is not None:
            entry["properties"]["score"] = f.score
        if f.location is not None:
            region = {"startLine": f.location.line} if f.location.line else {}
            physical: dict[str, Any] = {"artifactLocation": {"uri": f.location.path}}
            if region:
                physical["region"] = region
            entry["locations"] = [{"physicalLocation": physical}]
        results.append(entry)
    doc = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "squatwatch",
                        "version": __version__,
                        "rules": rules,
                    }
                },
                "results": results,
            }
        ],
    }
    return json.dumps(doc, indent=2) + "\n"
