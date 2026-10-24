"""Shared vocabulary for build-hook findings (Python and npm)."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

from squatwatch.models import Finding, Location, Severity


class Capability(StrEnum):
    """What a build-time code path is able to do."""

    NETWORK = "network"
    PROCESS = "process"
    DYNAMIC_CODE = "dynamic-code"
    ENV = "env"
    SENSITIVE_FILE = "sensitive-file"
    OBFUSCATION = "obfuscation"


CAPABILITY_RULE: dict[Capability, str] = {
    Capability.NETWORK: "SW301",
    Capability.PROCESS: "SW302",
    Capability.DYNAMIC_CODE: "SW303",
    Capability.ENV: "SW304",
    Capability.OBFUSCATION: "SW305",
    Capability.SENSITIVE_FILE: "SW306",
}

CAPABILITY_TITLE: dict[Capability, str] = {
    Capability.NETWORK: "network access in build/install code",
    Capability.PROCESS: "process execution in build/install code",
    Capability.DYNAMIC_CODE: "dynamic code execution in build/install code",
    Capability.ENV: "environment access in build/install code",
    Capability.OBFUSCATION: "encoded or obfuscated data in build/install code",
    Capability.SENSITIVE_FILE: "reference to credential or key files in build/install code",
}

#: Environment variable names that usually hold credentials.
SECRET_ENV = re.compile(
    r"(TOKEN|SECRET|PASSW|PWD|API_?KEY|ACCESS_?KEY|PRIVATE|CREDENTIAL|AUTH|SESSION|"
    r"^AWS_|^NPM_|^PYPI_|^GITHUB_|^GH_|^GITLAB_|^AZURE_|^GCP_|^GOOGLE_)",
    re.IGNORECASE,
)

#: Path fragments of files that hold credentials or keys.
SENSITIVE_PATHS: tuple[str, ...] = (
    ".ssh",
    "id_rsa",
    "id_ed25519",
    "id_ecdsa",
    ".aws/credentials",
    ".aws\\credentials",
    ".npmrc",
    ".pypirc",
    ".netrc",
    ".gnupg",
    ".git-credentials",
    ".docker/config.json",
    ".kube/config",
    "login data",
    "local state",
    "wallet.dat",
    "/etc/passwd",
    "/etc/shadow",
    "keychain",
)

#: Execution context of a code location, from most to least certain to run.
CONTEXT_RUNS = frozenset({"module", "install-hook", "build-backend", "lifecycle-script"})


def mentions_sensitive_path(text: str) -> str | None:
    """Return the sensitive path fragment ``text`` mentions, if any."""
    low = text.lower()
    for frag in SENSITIVE_PATHS:
        if frag in low:
            return frag
    return None


@dataclass(slots=True)
class Hit:
    """One observed capability use before it becomes a :class:`Finding`."""

    capability: Capability
    severity: Severity
    line: int | None
    detail: str
    context: str
    evidence: dict[str, Any] = field(default_factory=dict)
    secret: bool = False
    rule: str | None = None
    title: str | None = None
    path: str | None = None

    def runs(self) -> bool:
        """Whether this code runs during build/install for certain."""
        return self.context in CONTEXT_RUNS


def finalise(hits: list[Hit], path: str, *, package: str | None = None) -> list[Finding]:
    """Turn hits into findings: downgrade unreachable code, add the composite
    exfiltration finding (SW309), and de-duplicate by (rule, line, detail)."""
    findings: list[Finding] = []
    seen: set[tuple[str, str | None, int | None, str]] = set()
    for hit in hits:
        severity = hit.severity if hit.runs() else hit.severity.lowered()
        rule = hit.rule or CAPABILITY_RULE[hit.capability]
        key = (rule, hit.path, hit.line, hit.detail)
        if key in seen:
            continue
        seen.add(key)
        context_note = "" if hit.runs() else " (in code not proven to run at install)"
        findings.append(
            Finding(
                rule=rule,
                severity=severity,
                title=hit.title or CAPABILITY_TITLE[hit.capability],
                message=f"{hit.detail}{context_note}",
                location=Location(hit.path or path, hit.line),
                package=package,
                evidence={"context": hit.context, **hit.evidence},
            )
        )
    running = [h for h in hits if h.runs()]
    takes = [
        h
        for h in running
        if h.capability is Capability.SENSITIVE_FILE
        or (h.capability is Capability.ENV and h.secret)
    ]
    sends = [h for h in running if h.capability is Capability.NETWORK]
    if takes and sends:
        findings.append(
            Finding(
                rule="SW309",
                severity=Severity.CRITICAL,
                title="possible credential exfiltration at install time",
                message=(
                    "install-time code both reads secrets/credential files "
                    f"(line {takes[0].line}) and opens network connections "
                    f"(line {sends[0].line})"
                ),
                location=Location(takes[0].path or path, takes[0].line),
                package=package,
                evidence={
                    "reads": [h.detail for h in takes][:5],
                    "sends": [h.detail for h in sends][:5],
                },
            )
        )
    return findings
