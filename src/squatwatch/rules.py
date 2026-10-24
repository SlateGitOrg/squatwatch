"""Catalogue of every rule squatwatch can report (used by SARIF and docs)."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class Rule:
    """Static description of a rule."""

    id: str
    name: str
    summary: str


RULES: dict[str, Rule] = {
    r.id: r
    for r in (
        Rule("SW101", "typo-squat", "Name is a keyboard/edit-distance typo of a popular package."),
        Rule(
            "SW102",
            "homoglyph-squat",
            "Name renders like a popular package using look-alike glyphs.",
        ),
        Rule(
            "SW103",
            "separator-squat",
            "Name changes separators or word order of a popular package.",
        ),
        Rule(
            "SW104",
            "scope-squat",
            "npm scope trick: typo'd scope, flattened or re-scoped popular package.",
        ),
        Rule(
            "SW105",
            "combo-squat",
            "Popular name combined with a generic term (-js, -dev, python3-...).",
        ),
        Rule(
            "SW106",
            "invalid-name",
            "Name is not valid for the registry or contains non-ASCII characters.",
        ),
        Rule(
            "SW201",
            "internal-name-public",
            "An internal package name exists on the public registry.",
        ),
        Rule("SW202", "internal-name-unclaimed", "An internal package name is unclaimed publicly."),
        Rule(
            "SW203",
            "internal-resolved-public",
            "Lockfile resolved an internal package from a public registry.",
        ),
        Rule(
            "SW204",
            "merged-indexes",
            "Package indexes are merged (pip --extra-index-url and equivalents).",
        ),
        Rule(
            "SW205",
            "unmapped-npm-scope",
            "Internal npm scope has no private registry mapping in .npmrc.",
        ),
        Rule("SW206", "unscoped-internal-npm", "Internal npm package is not under a scope."),
        Rule("SW300", "unreviewable-build-script", "Build script could not be parsed for review."),
        Rule("SW301", "hook-network", "Build/install code opens network connections."),
        Rule("SW302", "hook-process", "Build/install code starts processes."),
        Rule(
            "SW303", "hook-dynamic-code", "Build/install code executes dynamically produced code."
        ),
        Rule("SW304", "hook-env", "Build/install code reads environment variables or secrets."),
        Rule(
            "SW305",
            "hook-obfuscation",
            "Build/install code decodes embedded data (critical when executed).",
        ),
        Rule(
            "SW306",
            "hook-credential-path",
            "Build/install code references credential or key files.",
        ),
        Rule("SW307", "install-hook-present", "Package runs custom code at install time."),
        Rule("SW308", "build-backend", "In-tree or uncommon PEP 517 build backend."),
        Rule(
            "SW309",
            "hook-exfiltration",
            "Install code reads secrets and opens network connections.",
        ),
        Rule(
            "SW310",
            "download-and-execute",
            "Install script pipes downloaded content into an interpreter.",
        ),
        Rule(
            "SW311", "unsafe-archive-entry", "Archive entry is a link, device or escapes the root."
        ),
        Rule("SW312", "executable-pth", ".pth file executes code at interpreter start-up."),
    )
}
