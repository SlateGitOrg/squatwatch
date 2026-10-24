# Data

squatwatch ships two kinds of data: the **popular-package snapshots** the detector
compares names against, and the **evaluation data** used to measure it. All of it
is package *names*. No package code, artifacts, or personal data are stored. Total
committed data is about 0.6 MB.

## Popular-package snapshots (runtime data)

| File | What | Source | Pinned by | Licence |
|---|---|---|---|---|
| `src/squatwatch/data/popular-pypi.txt` | PyPI projects ranked 1–12,000 by 30-day downloads | [hugovk/top-pypi-packages](https://github.com/hugovk/top-pypi-packages), file `top-pypi-packages.min.json` at commit `e6b5b398c1fcc783f593031f99bc2c772d64c6ef` (data dated 2026-10-01) | SHA-256 `55fee05ed02b628f05350a51780ec436efae39ea0810df5d5419e15b850c7041` | The repository has no licence file. Only the project names and their order are kept (no download counts). Package names are public registry facts. If this matters for your use, regenerate from your own BigQuery export. |
| `src/squatwatch/data/popular-npm.txt` | npm packages ranked 1–14,000 in npm's "high-impact" list (≥1M weekly downloads or ≥500 dependents) | [`npm-high-impact@1.13.0`](https://www.npmjs.com/package/npm-high-impact) by Titus Wormer, file `lib/top.js` | SHA-256 of the tarball `63ed31dacc861ac10c95b47af242a984f210f0170eaea8eaa66ba4a9b8f9d30b` | MIT |

Regenerate both with `make snapshot` (`scripts/fetch_popular.py`). It needs network
access and fails on any checksum mismatch. The upstream npm list itself says that
"not all of these packages are popular" because download counts can be gamed, so a
squat that inflated its own downloads could appear in the snapshot. See the
README's Limitations section.

## Evaluation data (`data/eval/`)

| File | Rows | What | Label basis |
|---|---|---|---|
| `incidents.csv` | 639 | Names of malicious packages from documented incidents, with the package each one imitated, the incident id, year and source URL | Malicious per the cited source. The `target_basis` column says whether the imitated package was **stated** by the source, **inferred** by `scripts/build_incidents.py`, or **unknown**. |
| `dev-exposed.txt` | 18 | Incident names that were visible during development (unit tests, demo fixtures, docstrings, rule examples) | Not a label. `squatwatch eval` moves these names out of the held-out test split and reports them separately. The rule and the guard test are described in the file header and DECISIONS.md. |
| `benign-pypi.txt` | 3,000 | PyPI ranks 12,001–15,000 from the same pinned file (not in the snapshot) | *Assumed* benign because they are widely downloaded |
| `benign-npm.txt` | 3,338 | npm high-impact ranks 14,001–17,338 (not in the snapshot) | *Assumed* benign (same caveat as the snapshot about gamed downloads) |

### Incident sources

| Incident id | Names | Source |
|---|---|---|
| `skcsirt-2017` | 10 PyPI | SK-CSIRT advisory SA-20170909, as listed by [BleepingComputer](https://www.bleepingcomputer.com/news/security/ten-malicious-libraries-found-on-pypi-python-package-index/) |
| `npm-hacktask-2017` | 38 npm | [npm blog: "crossenv malware on the npm registry"](https://blog.npmjs.org/post/163723642530/crossenv-malware-on-the-npm-registry) (targets inferred, not stated) |
| `pypi-2018-10` | 5 PyPI | [Slashdot summary of the October 2018 PyPI removals](https://developers.slashdot.org/story/18/10/27/1820259/twelve-malicious-python-libraries-found-and-removed-from-pypi) |
| `pypi-2019-12` | 2 PyPI | [Snyk: malicious packages typo-squatting in PyPI](https://snyk.io/blog/malicious-packages-found-to-be-typo-squatting-in-pypi/) (`jeIlyfish`, `python3-dateutil`) |
| `npm-2020-09` | 4 npm | [Sonatype: malicious npm packages broadcast user data](https://www.sonatype.com/blog/sonatype-spots-malicious-npm-packages) |
| `npm-2020-11` | 1 npm | [Sonatype: `twilio-npm`](https://www.sonatype.com/blog/twilio-npm-is-brandjacking-malware-in-disguise) |
| `iconburst-2022` | 2 npm | [ReversingLabs: IconBurst](https://www.reversinglabs.com/blog/iconburst-npm-software-supply-chain-attack-grabs-data-from-apps-websites) |
| `pypi-2024-03` | 576 PyPI (566 typosquats + 10 non-typosquat seed packages) | [Phylum, now hosted by Veracode: "Typosquatting campaign targets Python developers"](https://www.veracode.com/blog/typosquatting-campaign-targets-python-developers/). The names come from the article's full package list. The article gives no per-package target, so each name was assigned to the closest of the campaign's named targets (case-folded OSA distance). Typos of `requirements` (the file name, not a package) have no target. |
| `pytorch-2022-12` | 1 PyPI | [PyTorch: compromised nightly dependency](https://pytorch.org/blog/compromised-nightly-dependency/) (`torchtriton`, a dependency-confusion case kept as `kind=confusion` and excluded from the typosquat metrics) |

`incidents.csv` was built with `make incidents` (`scripts/build_incidents.py`). The
script holds the hand-curated rows and extracts the 2024 list from the article.
Web pages are not pinned by checksum, so a rebuild may differ if the article
changes. The committed CSV is the canonical copy.

Known label noise:
- `mariadb` (npm, 2017) has since become a legitimate package name.
- Several 2017 npm names target packages that are not on npm or are not popular
  (`tkinter`, `smb`, `sqlserver`).
- Inferred targets are a labelling assumption.

### Generated variants

`squatwatch.evaluation.generate_variants` creates one synthetic squat per technique
for 400 randomly sampled popular names per ecosystem (ranks ≤ 3,000; seed 1337).
The techniques are omission, repetition, insertion, transposition, keyboard slip,
random substitution, double edit, homoglyph, separator change, combo term, and
(npm scoped targets only) scope tricks. Variants that collide with a popular,
benign or incident name are dropped. These are synthetic, and their technique
families overlap the detector's by construction. Treat their recall as a
regression check, not as evidence of real-world performance.

## Benign test archives (`examples/archives/`)

Six small archives written by `scripts/build_archives.py` are byte-reproducible
(fixed mtimes, ordering and gzip header), and `make check` verifies them. They are
**inert fixtures written for this repository**. Their "network" calls target
`127.0.0.1:9` or never run, their "secrets" are fixture variable names, and the
one encoded payload decodes to a `print` statement. They contain no third-party
code.
