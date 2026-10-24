# Threat model

squatwatch is a **defensive, advisory** tool. It reads dependency manifests,
lockfiles and package archives, and reports names and build hooks that look like
supply-chain attacks. It never installs, imports or executes anything it scans,
and it contacts public registries only when explicitly asked (`--online`).

## Assets protected

- Developer machines and CI runners that install dependencies: credentials in
  environment variables, `~/.npmrc`, `~/.pypirc`, SSH keys, cloud credentials.
- The integrity of builds that mix private and public package indexes.

## Adversaries and the attacks in scope

| Attack | Adversary capability | What squatwatch checks |
|---|---|---|
| Typosquatting | Registers a public package whose name is a likely typo of a popular one | Edit-distance, keyboard, homoglyph, separator, token-order signals against a popularity snapshot (SW101–SW103) |
| Combosquatting / brandjacking | Registers `popular-js`, `python3-popular`, `twilio-npm` | Combo terms, glued affixes, version digits (SW105) |
| npm scope tricks | Registers a look-alike scope (`@typess`), a flattened name (`types-node`) or re-publishes under its own scope | Scope signals (SW104) |
| Homoglyph names | Uses `I`/`l`, `0`/`o`, Cyrillic letters | Confusable skeleton, non-ASCII detection (SW102, SW106) |
| Dependency confusion | Publishes a package under an organisation's internal name on the public registry, usually with a very high version | Internal-name exposure via a registry client (SW201/SW202), lockfile proof (SW203), index-merging config (SW204–SW206) |
| Malicious install hooks | Ships code that runs at `pip install` / `npm install` | Static review of setup.py, PEP 517 backends, `.pth`, lifecycle scripts and the JS they run (SW300–SW312) |

## Out of scope

- **Account takeover / maintainer compromise** of a legitimate package (event-stream,
  ua-parser-js, ctx). The name is genuine, so name analysis cannot help, and a
  compromised package's hooks are only reviewed if you scan its archive.
- **Malicious code outside install time** (code that runs on import or call). The
  hook reviewer looks at what runs during build/install, plus `.pth` files.
- **Runtime behaviour.** No sandboxing or dynamic analysis is done.
- **Registries other than PyPI and npm**, and lockfile formats listed under
  Limitations in the README.

## Evasion (known blind spots)

squatwatch is a heuristic. An informed attacker can avoid it:

- by picking a name that is not close to any snapshot entry, or by targeting a
  package below the snapshot cutoff;
- by inflating their own package's downloads until it enters the npm high-impact
  list (the upstream list warns that it can be gamed);
- by hiding behaviour through aliasing, `getattr` chains, string building, or
  JavaScript indirection that the token-level reviewer does not resolve;
- by keeping install hooks clean and running the payload on first import.

Treat a clean result as "nothing obvious", not "safe".

## Security of squatwatch itself

squatwatch parses attacker-controlled input:

| Risk | Mitigation |
|---|---|
| Archive bombs | No extraction to disk. Member count (20,000), per-file (2 MB) and total (64 MB) read budgets |
| Path traversal / link tricks in archives | Absolute, `..`, symlink, hardlink and device entries are never read and are reported (SW311) |
| Code execution while "analysing" setup.py | Only `ast.parse` is used. Nothing is imported or executed. Dependency lists are recovered from literals only |
| Escaping a scanned directory | `DirectoryTree` resolves paths and refuses anything outside its root |
| Malformed JSON/TOML/YAML-ish lockfiles | Parsers collect errors per file and keep going. The CLI exits 3 so CI notices |
| Registry responses | HTTPS only. JSON is validated. Retries are bounded with backoff. Lookups are cached per run |
| Prompt/command injection via package metadata | No shell is ever invoked with scanned content |

## Ethics

The evaluation data contains package **names only** from public incident reports.
The test archives are inert fixtures written for this repository (localhost
discard-port URLs, fixture variable names, a `print` payload). No real malware is
stored or produced.
