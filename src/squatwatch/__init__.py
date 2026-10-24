"""squatwatch: typosquat and dependency-confusion detector for npm and PyPI.

Public API::

    from squatwatch import Scanner, load_config, NameChecker, PopularIndex, Ecosystem

    result = Scanner(load_config(None, search_dir=Path("."))).scan([Path(".")])
    for finding in result.sorted_findings():
        print(finding.severity.label, finding.rule, finding.message)
"""

__version__ = "0.1.0"

from squatwatch.checker import CheckerSettings, NameChecker, NameVerdict
from squatwatch.config import Config, load_config
from squatwatch.confusion import ConfusionChecker, InternalPolicy
from squatwatch.hooks.review import review_path
from squatwatch.models import (
    Dependency,
    Ecosystem,
    Finding,
    Location,
    ScanResult,
    Severity,
)
from squatwatch.popular import PopularIndex
from squatwatch.registry import FixtureRegistry, HttpRegistryClient, RegistryClient
from squatwatch.scanner import Scanner

__all__ = [
    "CheckerSettings",
    "Config",
    "ConfusionChecker",
    "Dependency",
    "Ecosystem",
    "Finding",
    "FixtureRegistry",
    "HttpRegistryClient",
    "InternalPolicy",
    "Location",
    "NameChecker",
    "NameVerdict",
    "PopularIndex",
    "RegistryClient",
    "ScanResult",
    "Scanner",
    "Severity",
    "__version__",
    "load_config",
    "review_path",
]
