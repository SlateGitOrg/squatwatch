"""Versions, registry clients (fake transport only) and dependency confusion."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from squatwatch.confusion import ConfusionChecker, InternalPolicy, host_of, is_public_url
from squatwatch.errors import ConfigError, RegistryError
from squatwatch.models import Dependency, DependencyKind, Ecosystem, Location, Severity
from squatwatch.parsers.base import IndexSetting, ParsedManifest
from squatwatch.registry import (
    FixtureRegistry,
    HttpRegistryClient,
    RegistryRecord,
    urllib_transport,
)
from squatwatch.versions import is_newer, max_version, semver_key

# ------------------------------------------------------------------- versions


def test_semver_ordering() -> None:
    order = [
        "1.0.0-alpha",
        "1.0.0-alpha.1",
        "1.0.0-alpha.beta",
        "1.0.0-beta.2",
        "1.0.0-beta.11",
        "1.0.0",
    ]
    keys = [semver_key(v) for v in order]
    assert all(k is not None for k in keys)
    assert keys == sorted(keys)  # type: ignore[type-var]
    assert semver_key("not-a-version") is None
    assert semver_key("v2.0.0+build.5") == (2, 0, 0, 1, ())


def test_max_version_and_is_newer() -> None:
    assert max_version(Ecosystem.PYPI, ["1.0", "1.10", "1.9", "garbage"]) == "1.10"
    assert max_version(Ecosystem.NPM, ["1.0.0", "1.10.0", "1.9.0", "x"]) == "1.10.0"
    assert max_version(Ecosystem.NPM, []) is None
    assert is_newer(Ecosystem.PYPI, "99.0.0", "1.4.0") is True
    assert is_newer(Ecosystem.PYPI, "x", "1.0") is None
    assert is_newer(Ecosystem.NPM, "1.0.0", "2.0.0") is False
    assert is_newer(Ecosystem.NPM, "x", "2.0.0") is None


# ------------------------------------------------------------------- registry


def test_fixture_registry(tmp_path: Path) -> None:
    path = tmp_path / "reg.json"
    path.write_text(json.dumps({"pypi": {"Acme_Billing": {"versions": ["1.0", "2.0"]}}}))
    reg = FixtureRegistry.from_file(path)
    rec = reg.lookup(Ecosystem.PYPI, "acme-billing")
    assert rec.exists and rec.latest == "2.0"
    assert not reg.lookup(Ecosystem.NPM, "acme-billing").exists
    assert reg.calls == [(Ecosystem.PYPI, "acme-billing"), (Ecosystem.NPM, "acme-billing")]


@pytest.mark.parametrize(
    "payload",
    ['{"pypi": []}', '{"pypi": {"x": {"versions": [1]}}}', "[]", "{bad"],
)
def test_fixture_registry_rejects_bad_data(tmp_path: Path, payload: str) -> None:
    path = tmp_path / "reg.json"
    path.write_text(payload)
    with pytest.raises(ConfigError):
        FixtureRegistry.from_file(path)


class FakeTransport:
    def __init__(self, responses: list[tuple[int, bytes] | Exception]) -> None:
        self.responses = responses
        self.urls: list[str] = []

    def __call__(self, url: str, timeout: float) -> tuple[int, bytes]:
        self.urls.append(url)
        item = self.responses.pop(0)
        if isinstance(item, Exception):
            raise item
        return item


def test_http_client_parses_pypi_and_caches() -> None:
    body = json.dumps({"releases": {"1.0": [], "2.0": []}}).encode()
    transport = FakeTransport([(200, body)])
    client = HttpRegistryClient(transport, sleep=lambda _: None)
    rec = client.lookup(Ecosystem.PYPI, "Acme_Billing")
    assert rec.exists and rec.versions == ("1.0", "2.0")
    assert client.lookup(Ecosystem.PYPI, "acme-billing") is rec  # cached by match key
    assert transport.urls == ["https://pypi.org/pypi/Acme_Billing/json"]


def test_http_client_npm_scoped_url_and_404() -> None:
    transport = FakeTransport([(404, b""), (200, json.dumps({"versions": {"1.0.0": {}}}).encode())])
    client = HttpRegistryClient(transport, sleep=lambda _: None)
    assert not client.lookup(Ecosystem.NPM, "@acme/ui-kit").exists
    assert client.lookup(Ecosystem.NPM, "left-pad").versions == ("1.0.0",)
    assert transport.urls[0] == "https://registry.npmjs.org/@acme%2Fui-kit"


def test_http_client_retries_transient_failures() -> None:
    sleeps: list[float] = []
    transport = FakeTransport([OSError("reset"), (503, b""), (200, b'{"releases": {}}')])
    client = HttpRegistryClient(transport, retries=2, backoff=0.5, sleep=sleeps.append)
    assert client.lookup(Ecosystem.PYPI, "x").exists
    assert sleeps == [0.5, 1.0]


def test_http_client_gives_up_and_rejects_bad_responses() -> None:
    client = HttpRegistryClient(FakeTransport([(500, b"")] * 3), retries=2, sleep=lambda _: None)
    with pytest.raises(RegistryError, match="after 3 attempts"):
        client.lookup(Ecosystem.PYPI, "x")
    with pytest.raises(RegistryError, match="unexpected HTTP status 403"):
        HttpRegistryClient(FakeTransport([(403, b"")])).lookup(Ecosystem.PYPI, "y")
    with pytest.raises(RegistryError, match="invalid JSON"):
        HttpRegistryClient(FakeTransport([(200, b"{")])).lookup(Ecosystem.PYPI, "z")
    with pytest.raises(RegistryError, match="JSON object"):
        HttpRegistryClient(FakeTransport([(200, b"[]")])).lookup(Ecosystem.PYPI, "w")


def test_default_transport_refuses_non_https() -> None:
    with pytest.raises(RegistryError, match="non-HTTPS"):
        urllib_transport("http://pypi.org/pypi/x/json", 1.0)


# ------------------------------------------------------------------ confusion


def dep(
    name: str,
    eco: Ecosystem,
    *,
    version: str | None = None,
    resolved: str | None = None,
    kind: DependencyKind = DependencyKind.RUNTIME,
    path: str = "m",
) -> Dependency:
    return Dependency(
        name=name,
        ecosystem=eco,
        location=Location(path, 1),
        version=version,
        resolved=resolved,
        kind=kind,
    )


def manifest(
    eco: Ecosystem, deps: list[Dependency], indexes: list[IndexSetting] | None = None
) -> ParsedManifest:
    return ParsedManifest(path="m", ecosystem=eco, dependencies=deps, indexes=indexes or [])


POLICY = InternalPolicy(
    names=frozenset({"Acme_Billing"}), patterns=("acme-*",), npm_scopes=("@acme",)
)


def test_policy_matching() -> None:
    assert POLICY.is_internal(Ecosystem.PYPI, "acme-billing")
    assert POLICY.is_internal(Ecosystem.PYPI, "ACME-anything")
    assert POLICY.is_internal(Ecosystem.NPM, "@ACME/ui")
    assert not POLICY.is_internal(Ecosystem.NPM, "@other/ui")
    assert not POLICY.is_internal(Ecosystem.PYPI, "requests")
    assert InternalPolicy().empty and not POLICY.empty
    assert host_of("https://Registry.NPMJS.org/x") == "registry.npmjs.org"
    assert is_public_url("https://files.pythonhosted.org/x.whl")
    assert not is_public_url("https://pypi.corp.example/simple")


def test_exposure_findings_by_version() -> None:
    reg = FixtureRegistry(
        {"pypi": {"acme-billing": {"versions": ["0.1", "99.0"]}, "acme-low": {"versions": ["0.1"]}}}
    )
    checker = ConfusionChecker(POLICY, reg)
    findings = checker.check(
        [
            manifest(
                Ecosystem.PYPI,
                [
                    dep("acme-billing", Ecosystem.PYPI, version="1.4.0"),
                    dep("acme-low", Ecosystem.PYPI, version="2.0"),
                    dep("acme-new", Ecosystem.PYPI),
                    dep("requests", Ecosystem.PYPI),
                ],
            )
        ]
    )
    by = {(f.rule, f.package): f.severity for f in findings}
    assert by[("SW201", "acme-billing")] is Severity.CRITICAL
    assert by[("SW201", "acme-low")] is Severity.HIGH
    assert by[("SW202", "acme-new")] is Severity.MEDIUM
    assert not any(f.package == "requests" for f in findings)


def test_resolved_from_public_registry_is_critical() -> None:
    checker = ConfusionChecker(POLICY)
    findings = checker.check(
        [
            manifest(
                Ecosystem.NPM,
                [
                    dep(
                        "@acme/ui",
                        Ecosystem.NPM,
                        resolved="https://registry.npmjs.org/@acme/ui/-/ui-1.0.0.tgz",
                        kind=DependencyKind.LOCKED,
                    ),
                    dep(
                        "@acme/ok",
                        Ecosystem.NPM,
                        resolved="https://npm.acme.example/@acme/ok.tgz",
                        kind=DependencyKind.LOCKED,
                    ),
                ],
            )
        ]
    )
    sw203 = [f for f in findings if f.rule == "SW203"]
    assert [f.package for f in sw203] == ["@acme/ui"]
    assert sw203[0].severity is Severity.CRITICAL


def test_index_configuration_findings() -> None:
    loc = Location("requirements.txt", 2)
    merged = manifest(
        Ecosystem.PYPI,
        [dep("acme-x", Ecosystem.PYPI)],
        [
            IndexSetting("https://pypi.corp/simple", "extra", loc),
            IndexSetting("https://mirror/simple", "primary", loc),
        ],
    )
    findings = ConfusionChecker(POLICY).check([merged])
    assert [(f.rule, f.severity) for f in findings] == [("SW204", Severity.HIGH)]
    no_internal = ConfusionChecker(InternalPolicy()).check(
        [manifest(Ecosystem.PYPI, [], [IndexSetting("https://x/simple", "supplemental", loc)])]
    )
    assert [(f.rule, f.severity) for f in no_internal] == [("SW204", Severity.MEDIUM)]


def test_npm_scope_mapping_findings() -> None:
    policy = InternalPolicy(names=frozenset({"acme-util"}), npm_scopes=("@acme",))
    deps = [
        dep("@acme/a", Ecosystem.NPM),
        dep("@acme/b", Ecosystem.NPM),
        dep("acme-util", Ecosystem.NPM),
    ]
    findings = ConfusionChecker(policy).check([manifest(Ecosystem.NPM, deps)])
    assert sorted(f.rule for f in findings) == ["SW205", "SW206"]
    mapped = manifest(
        Ecosystem.NPM, [], [IndexSetting("https://npm.acme/", "scope", Location(".npmrc"), "@acme")]
    )
    findings = ConfusionChecker(policy).check([manifest(Ecosystem.NPM, deps), mapped])
    assert [f.rule for f in findings] == ["SW206"]


def test_registry_errors_are_collected() -> None:
    class Broken:
        def lookup(self, ecosystem: Ecosystem, name: str) -> RegistryRecord:
            raise RegistryError("down")

    checker = ConfusionChecker(POLICY, Broken())
    assert checker.check([manifest(Ecosystem.PYPI, [dep("acme-x", Ecosystem.PYPI)])]) == []
    assert checker.errors and "down" in checker.errors[0]
