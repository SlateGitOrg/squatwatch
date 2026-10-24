"""Ecosystem-specific package-name rules: normalisation, scopes, tokens.

PyPI compares names after PEP 503 normalisation (runs of ``-``, ``_`` and ``.``
collapse to ``-``, case-insensitive), so ``Django_Rest`` and ``django-rest`` are
the *same* project and never a squat of one another. npm compares names exactly;
``cross-env`` and ``cross_env`` are different packages, which makes separator
swaps a real attack there. Legacy npm names may contain upper case, but the
registry rejects new names that differ from an existing one only by case, so
squatwatch compares npm names lower-cased.
"""

from __future__ import annotations

import re

from squatwatch.models import Ecosystem

_PYPI_NAME = re.compile(r"^([A-Z0-9]|[A-Z0-9][A-Z0-9._-]*[A-Z0-9])$", re.IGNORECASE)
_NPM_BASE = re.compile(r"^[a-z0-9~-][a-z0-9._~-]*$")
_SEP_RUN = re.compile(r"[-_.]+")
SEPARATORS = frozenset("-_.")
NPM_MAX_LENGTH = 214


def pypi_normalize(name: str) -> str:
    """PEP 503 normalised form of a PyPI project name."""
    return _SEP_RUN.sub("-", name.strip()).lower()


def split_scope(name: str) -> tuple[str | None, str]:
    """Split an npm name into ``(scope, base)``; scope includes the ``@``."""
    if name.startswith("@") and "/" in name:
        scope, _, base = name.partition("/")
        return scope, base
    return None, name


def match_key(name: str, ecosystem: Ecosystem) -> str:
    """The key under which the registry treats two names as identical."""
    if ecosystem is Ecosystem.PYPI:
        return pypi_normalize(name)
    return name.strip().lower()


def tokens(name: str, ecosystem: Ecosystem) -> tuple[str, ...]:
    """Lower-case word tokens of a name (the base name only, for npm)."""
    base = split_scope(name)[1] if ecosystem is Ecosystem.NPM else name
    return tuple(t for t in _SEP_RUN.split(base.lower()) if t)


def collapse(name: str, ecosystem: Ecosystem) -> str:
    """Remove every separator (and npm ``@``/``/``) from the lower-cased name."""
    key = match_key(name, ecosystem)
    return "".join(ch for ch in key if ch not in SEPARATORS and ch not in "@/")


def is_valid_name(name: str, ecosystem: Ecosystem) -> bool:
    """Whether ``name`` is syntactically acceptable to the registry.

    Non-ASCII names are *not* valid on either registry today, but they are still
    worth reporting: they show up in hand-edited manifests and in mirrors.
    """
    if ecosystem is Ecosystem.PYPI:
        return bool(_PYPI_NAME.match(name))
    if not name or len(name) > NPM_MAX_LENGTH:
        return False
    scope, base = split_scope(name)
    if scope is not None and not _NPM_BASE.match(scope[1:].lower()):
        return False
    return bool(_NPM_BASE.match(base.lower())) and not base.startswith((".", "_"))
