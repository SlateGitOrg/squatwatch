"""Exception hierarchy. Every error squatwatch raises on bad input derives from
:class:`SquatwatchError`, so callers can catch one type."""

from __future__ import annotations


class SquatwatchError(Exception):
    """Base class for all squatwatch errors."""


class ConfigError(SquatwatchError):
    """Invalid configuration file or option."""


class ParseError(SquatwatchError):
    """A manifest or lockfile could not be parsed."""

    def __init__(self, path: str, message: str, line: int | None = None) -> None:
        self.path = path
        self.line = line
        where = f"{path}:{line}" if line is not None else path
        super().__init__(f"{where}: {message}")


class RegistryError(SquatwatchError):
    """A registry lookup failed for a reason other than "package not found"."""


class ArchiveError(SquatwatchError):
    """An archive could not be read safely."""


class DataError(SquatwatchError):
    """Bundled or evaluation data is missing or malformed."""
