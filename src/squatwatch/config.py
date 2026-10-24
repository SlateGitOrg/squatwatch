"""Configuration: ``squatwatch.toml`` or ``[tool.squatwatch]`` in pyproject.toml.

Example::

    fail-on = "high"            # CI gate: lowest severity that fails the run
    min-score = 0.6             # typosquat reporting threshold (0..1)
    allow = ["pypi:requests-mock", "left-padx"]   # known-good look-alikes
    hooks = true                # review build/install hooks of scanned projects
    registry-fixture = "registry.json"           # offline registry answers

    [internal]                  # names that must never come from a public registry
    names = ["acme-billing"]
    patterns = ["acme-*"]
    npm-scopes = ["@acme"]

Unknown keys are rejected so typos in a security config fail loudly.
"""

from __future__ import annotations

import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from squatwatch.checker import CheckerSettings
from squatwatch.confusion import InternalPolicy
from squatwatch.errors import ConfigError
from squatwatch.models import Ecosystem, Severity

CONFIG_FILENAME = "squatwatch.toml"
_TOP_KEYS = frozenset({"fail-on", "min-score", "allow", "hooks", "registry-fixture", "internal"})
_INTERNAL_KEYS = frozenset({"names", "patterns", "npm-scopes"})


@dataclass(slots=True)
class Config:
    """Resolved settings for a scan."""

    fail_on: Severity = Severity.HIGH
    min_score: float = CheckerSettings().min_score
    allow: dict[Ecosystem, frozenset[str]] = field(
        default_factory=lambda: {eco: frozenset() for eco in Ecosystem}
    )
    hooks: bool = True
    registry_fixture: Path | None = None
    internal: InternalPolicy = field(default_factory=InternalPolicy)
    source: str | None = None

    def checker_settings(self, ecosystem: Ecosystem) -> CheckerSettings:
        """Name-checker settings for one ecosystem."""
        return CheckerSettings(min_score=self.min_score, allow=self.allow[ecosystem])


def _str_list(value: object, key: str) -> list[str]:
    if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
        raise ConfigError(f"{key} must be a list of strings")
    return list(value)


def parse_config(data: dict[str, Any], *, base_dir: Path, source: str) -> Config:
    """Validate a config mapping (already decoded from TOML)."""
    unknown = set(data) - _TOP_KEYS
    if unknown:
        raise ConfigError(f"{source}: unknown key(s): {', '.join(sorted(unknown))}")
    cfg = Config(source=source)
    if "fail-on" in data:
        if not isinstance(data["fail-on"], str):
            raise ConfigError(f"{source}: fail-on must be a string")
        cfg.fail_on = Severity.parse(data["fail-on"])
    if "min-score" in data:
        score = data["min-score"]
        if isinstance(score, bool) or not isinstance(score, (int, float)) or not 0 <= score <= 1:
            raise ConfigError(f"{source}: min-score must be a number between 0 and 1")
        cfg.min_score = float(score)
    if "hooks" in data:
        if not isinstance(data["hooks"], bool):
            raise ConfigError(f"{source}: hooks must be true or false")
        cfg.hooks = data["hooks"]
    if "registry-fixture" in data:
        if not isinstance(data["registry-fixture"], str):
            raise ConfigError(f"{source}: registry-fixture must be a path string")
        cfg.registry_fixture = base_dir / data["registry-fixture"]
    allow: dict[Ecosystem, set[str]] = {eco: set() for eco in Ecosystem}
    for entry in _str_list(data.get("allow", []), f"{source}: allow"):
        prefix, sep, name = entry.partition(":")
        if sep and prefix in {e.value for e in Ecosystem}:
            allow[Ecosystem(prefix)].add(name)
        else:
            for eco in Ecosystem:
                allow[eco].add(entry)
    cfg.allow = {eco: frozenset(names) for eco, names in allow.items()}
    internal = data.get("internal", {})
    if not isinstance(internal, dict):
        raise ConfigError(f"{source}: [internal] must be a table")
    unknown = set(internal) - _INTERNAL_KEYS
    if unknown:
        raise ConfigError(f"{source}: unknown key(s) in [internal]: {', '.join(sorted(unknown))}")
    scopes = _str_list(internal.get("npm-scopes", []), f"{source}: internal.npm-scopes")
    for scope in scopes:
        if not scope.startswith("@") or "/" in scope:
            raise ConfigError(f"{source}: npm scope {scope!r} must look like '@name'")
    cfg.internal = InternalPolicy(
        names=frozenset(_str_list(internal.get("names", []), f"{source}: internal.names")),
        patterns=tuple(_str_list(internal.get("patterns", []), f"{source}: internal.patterns")),
        npm_scopes=tuple(scopes),
    )
    return cfg


def load_config(path: Path | None = None, *, search_dir: Path | None = None) -> Config:
    """Load an explicit config file, or look for one in ``search_dir``.

    Lookup order without ``path``: ``squatwatch.toml``, then
    ``[tool.squatwatch]`` in ``pyproject.toml``. No file means defaults.
    """
    if path is not None:
        return _load_file(path, table=None if path.name != "pyproject.toml" else "tool.squatwatch")
    if search_dir is not None:
        candidate = search_dir / CONFIG_FILENAME
        if candidate.is_file():
            return _load_file(candidate, table=None)
        pyproject = search_dir / "pyproject.toml"
        if pyproject.is_file():
            try:
                data = tomllib.loads(pyproject.read_text(encoding="utf-8"))
            except (OSError, tomllib.TOMLDecodeError):
                return Config()
            tool = data.get("tool", {})
            if isinstance(tool, dict) and isinstance(tool.get("squatwatch"), dict):
                return parse_config(
                    tool["squatwatch"], base_dir=search_dir, source=f"{pyproject} [tool.squatwatch]"
                )
    return Config()


def _load_file(path: Path, *, table: str | None) -> Config:
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise ConfigError(f"cannot read config {path}: {exc}") from exc
    except tomllib.TOMLDecodeError as exc:
        raise ConfigError(f"invalid TOML in {path}: {exc}") from exc
    if table is not None:
        for part in table.split("."):
            nxt = data.get(part, {})
            if not isinstance(nxt, dict):
                raise ConfigError(f"{path}: [{table}] must be a table")
            data = nxt
    return parse_config(data, base_dir=path.parent, source=str(path))
