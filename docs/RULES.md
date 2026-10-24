# Rule reference

Severity for name rules (SW101–SW105) comes from the score: **HIGH** at ≥ 0.75,
**MEDIUM** at ≥ 0.65, otherwise **LOW**. Names under `min-score` (default 0.60)
are not reported. Other rules have fixed severities, shown below. For build-hook
rules, the severity drops one level when the code is not proven to run at install
time.

## Names

| Rule | Name | Example | Notes |
|---|---|---|---|
| SW101 | typo-squat | `reqeusts`, `urlib3`, `djanga`, `pytset` | omission, repetition, insertion, transposition, keyboard slip, substitution. Two edits are allowed on names of 8+ characters but weighted low (0.50), so most double-edit squats (`tensoflw`) stay below the default threshold |
| SW102 | homoglyph-squat | `jeIlyfish`, `pyth0n`, `rеquests` (Cyrillic е) | confusable skeleton match |
| SW103 | separator-squat | `setup-tools`, `crossenv`, `cross_env`, `dateutil-python` | separators changed or words reordered (on PyPI, `-`/`_`/`.` alone are the same project and never reported) |
| SW104 | scope-squat | `@typess/node`, `types-node`, `babelcli` | npm only. Names under a scope that already owns popular packages are trusted. Re-publishing a popular name under an unknown scope (`@evil/lodash`) is weighted low (0.50) and usually stays below the default threshold |
| SW105 | combo-squat | `twilio-npm`, `python3-dateutil`, `jquery.js`, `requests2` | generic terms only (`js`, `dev`, `utils`, `python3`...), not domain words like `cors` |
| SW106 | invalid-name | non-ASCII or syntactically invalid names | HIGH for non-ASCII, MEDIUM otherwise |

## Dependency confusion

| Rule | Severity | Meaning |
|---|---|---|
| SW201 | CRITICAL / HIGH | An internal name exists on the public registry. CRITICAL when the public version outranks the internal one (or the internal one is unpinned) |
| SW202 | MEDIUM | The internal name is unclaimed publicly. Anyone can register it |
| SW203 | CRITICAL | A lockfile shows an internal package was resolved from a public registry host |
| SW204 | HIGH / MEDIUM | Indexes are merged (`--extra-index-url`, Poetry supplemental/secondary, Pipfile with multiple sources, uv with `unsafe-best-match`). HIGH when internal packages are declared |
| SW205 | MEDIUM | An internal npm scope has no `@scope:registry=` mapping in `.npmrc` |
| SW206 | LOW | An internal npm package is unscoped |

## Build and install hooks

| Rule | Typical severity | Meaning |
|---|---|---|
| SW300 | MEDIUM | setup.py is not valid Python 3, so it could not be reviewed |
| SW301 | HIGH | Network access (`urllib.request.urlopen`, `requests`, `socket`, `curl`, `https` module...) |
| SW302 | MEDIUM | Process execution (`subprocess`, `os.system`, `child_process`) |
| SW303 | MEDIUM (LOW for `exec(open(...).read())`) | Dynamic code (`exec`, `eval`, `compile`, `Function`, `node -e`) |
| SW304 | HIGH for credential-like variables, MEDIUM for the whole environment, LOW otherwise | Environment access |
| SW305 | CRITICAL when decoded data is executed, MEDIUM otherwise | base64/hex/zlib/rot13 decoding, long encoded blobs |
| SW306 | HIGH | References to credential files (`.ssh`, `.npmrc`, `.pypirc`, `.aws/credentials`...) |
| SW307 | LOW (INFO for your own project) | Install hooks are present (custom setuptools commands, npm lifecycle scripts) |
| SW308 | MEDIUM in-tree backend, LOW uncommon backend | PEP 517 `backend-path` or an unknown `build-backend` |
| SW309 | CRITICAL | Install-time code both reads secrets/credential files and opens network connections |
| SW310 | CRITICAL | An install script pipes downloaded content into an interpreter (`curl ... \| sh`) |
| SW311 | HIGH (traversal/absolute/device), MEDIUM (links, member limit) | Unsafe archive entry |
| SW312 | HIGH | A `.pth` file with an `import` line runs at every interpreter start-up |
