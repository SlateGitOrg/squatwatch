"""Exception hierarchy. Every error squatwatch raises on bad input derives from
:class:`SquatwatchError`, so callers can catch one type."""

from __future__ import annotations


class SquatwatchError(Exception):
    """Base class for all squatwatch errors."""


class ConfigError(SquatwatchError):
    """Invalid configuration file or option."""


class RegistryError(SquatwatchError):
    """A registry lookup failed for a reason other than "package not found"."""


class ArchiveError(SquatwatchError):
    """An archive could not be read safely."""


class DataError(SquatwatchError):
    """Bundled or evaluation data is missing or malformed."""
