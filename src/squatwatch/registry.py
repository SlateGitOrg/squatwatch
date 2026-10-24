"""Pluggable public-registry clients for the dependency-confusion check.

:class:`RegistryClient` is a one-method protocol. Two implementations ship:

* :class:`FixtureRegistry` — answers from a JSON document; used by tests and
  ``make demo`` so nothing touches the network.
* :class:`HttpRegistryClient` — queries the PyPI JSON API and the npm registry.
  The HTTP transport is injectable (tests pass a fake), lookups are cached, and
  transient failures are retried with exponential backoff. It is only used when
  the user passes ``--online``.
"""

from __future__ import annotations

import json
import logging
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

from squatwatch import __version__
from squatwatch.errors import ConfigError, RegistryError
from squatwatch.models import Ecosystem
from squatwatch.names import match_key
from squatwatch.versions import max_version

log = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class RegistryRecord:
    """What the public registry knows about a name."""

    ecosystem: Ecosystem
    name: str
    exists: bool
    versions: tuple[str, ...] = ()

    @property
    def latest(self) -> str | None:
        """Highest published version, if any."""
        return max_version(self.ecosystem, self.versions)


class RegistryClient(Protocol):
    """Looks up a package name on a public registry."""

    def lookup(self, ecosystem: Ecosystem, name: str) -> RegistryRecord:
        """Return the record; ``exists=False`` when the name is unclaimed."""
        ...


class FixtureRegistry:
    """Registry answers from a mapping ``{"pypi": {name: {"versions": [...]}}, "npm": ...}``."""

    def __init__(self, data: Mapping[str, Any]) -> None:
        self._data: dict[Ecosystem, dict[str, tuple[str, ...]]] = {}
        for eco in Ecosystem:
            table = data.get(eco.value, {})
            if not isinstance(table, Mapping):
                raise ConfigError(f"registry fixture: {eco.value!r} must be an object")
            entries: dict[str, tuple[str, ...]] = {}
            for name, entry in table.items():
                versions = entry.get("versions", []) if isinstance(entry, Mapping) else []
                if not isinstance(versions, list) or not all(isinstance(v, str) for v in versions):
                    raise ConfigError(f"registry fixture: {eco.value}/{name}: bad versions")
                entries[match_key(name, eco)] = tuple(versions)
            self._data[eco] = entries
        self.calls: list[tuple[Ecosystem, str]] = []

    @classmethod
    def from_file(cls, path: Path) -> FixtureRegistry:
        """Load a fixture JSON file."""
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ConfigError(f"cannot load registry fixture {path}: {exc}") from exc
        if not isinstance(data, dict):
            raise ConfigError(f"registry fixture {path} must be a JSON object")
        return cls(data)

    def lookup(self, ecosystem: Ecosystem, name: str) -> RegistryRecord:
        self.calls.append((ecosystem, name))
        versions = self._data.get(ecosystem, {}).get(match_key(name, ecosystem))
        if versions is None:
            return RegistryRecord(ecosystem, name, exists=False)
        return RegistryRecord(ecosystem, name, exists=True, versions=versions)


Transport = Callable[[str, float], tuple[int, bytes]]


def urllib_transport(url: str, timeout: float) -> tuple[int, bytes]:
    """Default transport: GET ``url``; returns (status, body). 404 is not an error."""
    if not url.startswith("https://"):
        raise RegistryError(f"refusing non-HTTPS registry URL {url!r}")
    request = urllib.request.Request(  # noqa: S310 - scheme checked above
        url,
        headers={"Accept": "application/json", "User-Agent": f"squatwatch/{__version__}"},
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as resp:  # noqa: S310 - https only
            body: bytes = resp.read()
            return int(resp.status), body
    except urllib.error.HTTPError as exc:
        return exc.code, b""


class HttpRegistryClient:
    """Live lookups against pypi.org and registry.npmjs.org."""

    PYPI_URL = "https://pypi.org/pypi/{name}/json"
    NPM_URL = "https://registry.npmjs.org/{name}"

    def __init__(
        self,
        transport: Transport = urllib_transport,
        *,
        timeout: float = 10.0,
        retries: int = 2,
        backoff: float = 0.5,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self._transport = transport
        self._timeout = timeout
        self._retries = retries
        self._backoff = backoff
        self._sleep = sleep
        self._cache: dict[tuple[Ecosystem, str], RegistryRecord] = {}

    def url_for(self, ecosystem: Ecosystem, name: str) -> str:
        """Metadata URL for a name (npm scoped names keep ``@`` and encode ``/``)."""
        if ecosystem is Ecosystem.PYPI:
            return self.PYPI_URL.format(name=urllib.parse.quote(name, safe=""))
        return self.NPM_URL.format(name=urllib.parse.quote(name, safe="@"))

    def lookup(self, ecosystem: Ecosystem, name: str) -> RegistryRecord:
        key = (ecosystem, match_key(name, ecosystem))
        if key in self._cache:
            return self._cache[key]
        url = self.url_for(ecosystem, name)
        status, body = self._fetch(url)
        if status == 404:
            record = RegistryRecord(ecosystem, name, exists=False)
        elif status == 200:
            record = RegistryRecord(
                ecosystem, name, exists=True, versions=self._versions(ecosystem, body, url)
            )
        else:
            raise RegistryError(f"{url}: unexpected HTTP status {status}")
        self._cache[key] = record
        return record

    def _fetch(self, url: str) -> tuple[int, bytes]:
        attempt = 0
        while True:
            error: OSError | None = None
            try:
                status, body = self._transport(url, self._timeout)
            except OSError as exc:  # URLError is an OSError
                status, body, error = -1, b"", exc
            transient = status in (-1, 429) or status >= 500
            if not transient:
                return status, body
            if attempt >= self._retries:
                raise RegistryError(f"{url}: lookup failed after {attempt + 1} attempts") from error
            delay = self._backoff * (2**attempt)
            log.warning(
                "registry lookup %s failed (status %s); retrying in %.1fs", url, status, delay
            )
            self._sleep(delay)
            attempt += 1

    @staticmethod
    def _versions(ecosystem: Ecosystem, body: bytes, url: str) -> tuple[str, ...]:
        try:
            data = json.loads(body)
        except json.JSONDecodeError as exc:
            raise RegistryError(f"{url}: invalid JSON: {exc}") from exc
        if not isinstance(data, dict):
            raise RegistryError(f"{url}: expected a JSON object")
        field = "releases" if ecosystem is Ecosystem.PYPI else "versions"
        table = data.get(field)
        return tuple(sorted(table)) if isinstance(table, dict) else ()
