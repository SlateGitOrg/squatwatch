"""Build ``data/eval/incidents.csv``: malicious package *names* from documented
historical incidents, with the package each one imitated.

Only names are recorded — no code, no artifacts. Each row cites its public
source. Targets marked ``stated`` come from the source; ``inferred`` targets were
assigned by this script (see ``infer`` below) and are a labelling assumption.

The March 2024 PyPI campaign list is extracted from the Phylum write-up (now
hosted by Veracode). Its targets are not given per package, so each name is
assigned to the closest (restricted Damerau-Levenshtein, case-folded) of the
campaign's named targets — independently of squatwatch's own snapshot.

Usage:
    uv run python scripts/build_incidents.py [--phylum-html saved_page.html]
(network is needed when --phylum-html is not given; not part of make check)
"""

from __future__ import annotations

import argparse
import csv
import html
import re
import sys
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from squatwatch.text.distance import osa_distance

OUT = ROOT / "data" / "eval" / "incidents.csv"

SRC_NPM_2017 = "https://blog.npmjs.org/post/163723642530/crossenv-malware-on-the-npm-registry"
SRC_SKCSIRT = "https://www.bleepingcomputer.com/news/security/ten-malicious-libraries-found-on-pypi-python-package-index/"
SRC_2018 = "https://developers.slashdot.org/story/18/10/27/1820259/twelve-malicious-python-libraries-found-and-removed-from-pypi"
SRC_2019 = "https://snyk.io/blog/malicious-packages-found-to-be-typo-squatting-in-pypi/"
SRC_SONATYPE_2020 = "https://www.sonatype.com/blog/sonatype-spots-malicious-npm-packages"
SRC_TWILIO = "https://www.sonatype.com/blog/twilio-npm-is-brandjacking-malware-in-disguise"
SRC_ICONBURST = "https://www.reversinglabs.com/blog/iconburst-npm-software-supply-chain-attack-grabs-data-from-apps-websites"
SRC_PHYLUM = "https://www.veracode.com/blog/typosquatting-campaign-targets-python-developers/"

# (name, ecosystem, target, target_basis, incident, year, source)
CURATED: list[tuple[str, str, str, str, str, int, str]] = [
    # SK-CSIRT advisory SA-20170909 (targets as listed by the news coverage)
    ("acqusition", "pypi", "acquisition", "stated", "skcsirt-2017", 2017, SRC_SKCSIRT),
    ("apidev-coop", "pypi", "apidev-coop_cms", "stated", "skcsirt-2017", 2017, SRC_SKCSIRT),
    ("bzip", "pypi", "bz2file", "stated", "skcsirt-2017", 2017, SRC_SKCSIRT),
    ("crypt", "pypi", "crypto", "stated", "skcsirt-2017", 2017, SRC_SKCSIRT),
    (
        "django-server",
        "pypi",
        "django-server-guardian-api",
        "stated",
        "skcsirt-2017",
        2017,
        SRC_SKCSIRT,
    ),
    ("pwd", "pypi", "pwdhash", "stated", "skcsirt-2017", 2017, SRC_SKCSIRT),
    ("setup-tools", "pypi", "setuptools", "stated", "skcsirt-2017", 2017, SRC_SKCSIRT),
    ("telnet", "pypi", "telnetsrvlib", "stated", "skcsirt-2017", 2017, SRC_SKCSIRT),
    ("urlib3", "pypi", "urllib3", "stated", "skcsirt-2017", 2017, SRC_SKCSIRT),
    ("urllib", "pypi", "urllib3", "stated", "skcsirt-2017", 2017, SRC_SKCSIRT),
    # October 2018 PyPI removals
    ("colourama", "pypi", "colorama", "stated", "pypi-2018-10", 2018, SRC_2018),
    ("diango", "pypi", "django", "stated", "pypi-2018-10", 2018, SRC_2018),
    ("djago", "pypi", "django", "stated", "pypi-2018-10", 2018, SRC_2018),
    ("dajngo", "pypi", "django", "stated", "pypi-2018-10", 2018, SRC_2018),
    ("djanga", "pypi", "django", "stated", "pypi-2018-10", 2018, SRC_2018),
    # December 2019
    ("jeIlyfish", "pypi", "jellyfish", "stated", "pypi-2019-12", 2019, SRC_2019),
    ("python3-dateutil", "pypi", "python-dateutil", "stated", "pypi-2019-12", 2019, SRC_2019),
    # npm 2020 (Sonatype)
    ("electorn", "npm", "electron", "stated", "npm-2020-09", 2020, SRC_SONATYPE_2020),
    ("lodashs", "npm", "lodash", "inferred", "npm-2020-09", 2020, SRC_SONATYPE_2020),
    ("loadyaml", "npm", "", "unknown", "npm-2020-09", 2020, SRC_SONATYPE_2020),
    ("loadyml", "npm", "", "unknown", "npm-2020-09", 2020, SRC_SONATYPE_2020),
    ("twilio-npm", "npm", "twilio", "stated", "npm-2020-11", 2020, SRC_TWILIO),
    # IconBurst (2022)
    ("ionicio", "npm", "ionicons", "stated", "iconburst-2022", 2022, SRC_ICONBURST),
    ("umbrellaks", "npm", "umbrellajs", "stated", "iconburst-2022", 2022, SRC_ICONBURST),
]

# npm "hacktask" packages, August 2017; targets are not given by the source.
HACKTASK: dict[str, str] = {
    "babelcli": "babel-cli",
    "cross-env.js": "cross-env",
    "crossenv": "cross-env",
    "d3.js": "d3",
    "fabric-js": "fabric",
    "ffmepg": "ffmpeg",
    "gruntcli": "grunt-cli",
    "http-proxy.js": "http-proxy",
    "jquery.js": "jquery",
    "mariadb": "mariasql",
    "mongose": "mongoose",
    "mssql-node": "mssql",
    "mssql.js": "mssql",
    "mysqljs": "mysql",
    "node-fabric": "fabric",
    "node-opencv": "opencv",
    "node-opensl": "openssl",
    "node-openssl": "openssl",
    "node-sqlite": "sqlite",
    "node-tkinter": "",
    "nodecaffe": "",
    "nodefabric": "fabric",
    "nodeffmpeg": "ffmpeg",
    "nodemailer-js": "nodemailer",
    "nodemailer.js": "nodemailer",
    "nodemssql": "mssql",
    "noderequest": "request",
    "nodesass": "node-sass",
    "nodesqlite": "sqlite",
    "opencv.js": "opencv",
    "openssl.js": "openssl",
    "proxy.js": "proxy",
    "shadowsock": "shadowsocks",
    "smb": "",
    "sqlite.js": "sqlite",
    "sqliter": "sqlite",
    "sqlserver": "",
    "tkinter": "",
}

PHYLUM_TARGETS = (
    "requests",
    "py-cord",
    "colorama",
    "capmonstercloudclient",
    "pillow",
    "bip-utils",
    "tensorflow",
    "beautifulsoup",
    "pygame",
    "simplejson",
    "matplotlib",
    "pytorch",
    "customtkinter",
    "selenium",
    "playwright",
    "asyncio",
    "requirements",
)


def infer(name: str, targets: tuple[str, ...]) -> str:
    """Closest named target by case-folded OSA distance (ties: list order)."""
    folded = name.lower()
    return min(targets, key=lambda t: osa_distance(folded, t))


def phylum_names(page: str) -> list[str]:
    text = re.sub(r"<script.*?</script>|<style.*?</style>", "", page, flags=re.S)
    text = html.unescape(re.sub(r"<[^>]+>", "\n", text))
    names: list[str] = []
    for line in (ln.strip() for ln in text.splitlines()):
        m = re.fullmatch(r"([A-Za-z0-9][A-Za-z0-9._-]*)@(\d[\w.]*)", line)
        if m and m.group(1) not in names:
            names.append(m.group(1))
    return names


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--phylum-html", type=Path)
    args = ap.parse_args()
    if args.phylum_html:
        page = args.phylum_html.read_text(encoding="utf-8", errors="replace")
    else:
        req = urllib.request.Request(SRC_PHYLUM, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=60) as resp:
            page = resp.read().decode("utf-8", errors="replace")

    rows: list[dict[str, str]] = []
    for name, eco, target, basis, incident, year, source in CURATED:
        rows.append(_row(name, eco, target, basis, incident, year, source, "typosquat"))
    for name, target in HACKTASK.items():
        basis = "inferred" if target else "unknown"
        rows.append(
            _row(name, "npm", target, basis, "npm-hacktask-2017", 2017, SRC_NPM_2017, "typosquat")
        )
    phylum = phylum_names(page)
    for name in phylum:
        if name.startswith(("schubismomv3", "insanepackage", "johnhammond")):
            rows.append(
                _row(name, "pypi", "", "unknown", "pypi-2024-03", 2024, SRC_PHYLUM, "other")
            )
            continue
        target = infer(name, PHYLUM_TARGETS)
        if target == "requirements":
            target = ""  # a typo of the requirements.txt file name, not of a package
        rows.append(
            _row(
                name,
                "pypi",
                target,
                "inferred" if target else "unknown",
                "pypi-2024-03",
                2024,
                SRC_PHYLUM,
                "typosquat",
            )
        )
    rows.append(
        _row(
            "torchtriton",
            "pypi",
            "",
            "unknown",
            "pytorch-2022-12",
            2022,
            "https://pytorch.org/blog/compromised-nightly-dependency/",
            "confusion",
        )
    )
    OUT.parent.mkdir(parents=True, exist_ok=True)
    with OUT.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    print(f"wrote {OUT.relative_to(ROOT)}: {len(rows)} rows ({len(phylum)} from the 2024 campaign)")
    return 0


def _row(
    name: str, eco: str, target: str, basis: str, incident: str, year: int, source: str, kind: str
) -> dict[str, str]:
    return {
        "name": name,
        "ecosystem": eco,
        "target": target,
        "target_basis": basis,
        "kind": kind,
        "incident": incident,
        "year": str(year),
        "source": source,
    }


if __name__ == "__main__":
    sys.exit(main())
