"""Review of npm lifecycle script command lines.

``scripts.preinstall``/``install``/``postinstall``/``prepare`` run automatically
when a package is installed (``prepare`` for git and local installs). The
command line is tokenised with :mod:`shlex` (punctuation-aware), split into
pipelines on ``;``, ``&&``, ``||``, ``&``, and each pipeline into commands on
``|``. Rules work on that structure:

* a network fetcher (``curl``, ``wget``...) piped into an interpreter is
  download-and-execute (SW310, critical);
* ``node -e``, ``python -c``, ``eval`` are inline dynamic code;
* ``$SECRET``-style variables, ``env``/``printenv``, credential paths;
* ``base64 -d`` decoding, escalated when piped into an interpreter;
* ``node <file>`` hands the file to the JavaScript reviewer when available.
"""

from __future__ import annotations

import re
import shlex
from collections.abc import Callable

from squatwatch.hooks.common import SECRET_ENV, Capability, Hit, mentions_sensitive_path
from squatwatch.hooks.jsscan import review_js
from squatwatch.models import Severity

INSTALL_HOOKS: tuple[str, ...] = (
    "preinstall",
    "install",
    "postinstall",
    "preprepare",
    "prepare",
    "postprepare",
)
FETCHERS = frozenset(
    {"curl", "wget", "fetch", "nc", "ncat", "netcat", "telnet", "ftp", "scp", "ssh"}
)
INTERPRETERS = frozenset(
    {
        "sh",
        "bash",
        "zsh",
        "dash",
        "ksh",
        "node",
        "python",
        "python3",
        "perl",
        "ruby",
        "php",
        "pwsh",
        "powershell",
    }
)
_INLINE_FLAGS = {
    "node": ("-e", "--eval", "-p", "--print"),
    "python": ("-c",),
    "python3": ("-c",),
    "perl": ("-e",),
}
_ENV_REF = re.compile(r"\$\{?([A-Za-z_][A-Za-z0-9_]*)\}?|%([A-Za-z_][A-Za-z0-9_]*)%")
_SEQUENCE_OPS = frozenset({";", "&&", "||", "&", "\n"})
_PREFIX_WORDS = frozenset({"sudo", "exec", "nohup", "time", "command"})

ReadFile = Callable[[str], str | None]


def _tokens(command: str) -> list[str]:
    lexer = shlex.shlex(command, posix=True, punctuation_chars=";&|")
    lexer.whitespace_split = True
    lexer.commenters = ""
    try:
        return list(lexer)
    except ValueError:
        return command.split()


def _pipelines(tokens: list[str]) -> list[list[list[str]]]:
    """[[cmd, cmd, ...] per pipeline] where each cmd is a word list."""
    pipelines: list[list[list[str]]] = [[[]]]
    for tok in tokens:
        if tok in _SEQUENCE_OPS:
            pipelines.append([[]])
        elif tok == "|":
            pipelines[-1].append([])
        elif tok == "||":
            pipelines.append([[]])
        else:
            pipelines[-1][-1].append(tok)
    return [[c for c in p if c] for p in pipelines if any(p)]


def _program(words: list[str]) -> tuple[str, list[str]]:
    """Strip ``VAR=value`` assignments and prefix words; return (program, args)."""
    i = 0
    while i < len(words) and (re.match(r"^[A-Za-z_]\w*=", words[i]) or words[i] in _PREFIX_WORDS):
        i += 1
    if i >= len(words):
        return "", []
    prog = words[i].rsplit("/", 1)[-1]
    return prog, words[i + 1 :]


def review_script(
    hook: str,
    command: str,
    *,
    read_file: ReadFile | None = None,
) -> list[Hit]:
    """Review one lifecycle script command line."""
    hits: list[Hit] = []
    ctx = "lifecycle-script"

    def add(cap: Capability, sev: Severity, detail: str, **kw: object) -> None:
        secret = bool(kw.pop("secret", False))
        rule = kw.pop("rule", None)
        title = kw.pop("title", None)
        hits.append(
            Hit(
                cap,
                sev,
                None,
                f"{hook}: {detail}",
                ctx,
                {"script": hook, **kw},
                secret=secret,
                rule=rule if isinstance(rule, str) else None,
                title=title if isinstance(title, str) else None,
            )
        )

    tokens = _tokens(command)
    for word in tokens:
        for m in _ENV_REF.finditer(word):
            var = m.group(1) or m.group(2)
            if SECRET_ENV.search(var):
                add(
                    Capability.ENV,
                    Severity.HIGH,
                    f"expands credential-like variable ${var}",
                    secret=True,
                )
        frag = mentions_sensitive_path(word)
        if frag is not None:
            add(Capability.SENSITIVE_FILE, Severity.HIGH, f"references credential path {frag!r}")

    for pipeline in _pipelines(tokens):
        programs = [_program(cmd) for cmd in pipeline]
        fetch_seen = False
        decode_seen = False
        for prog, args in programs:
            if prog in FETCHERS:
                fetch_seen = True
                add(Capability.NETWORK, Severity.HIGH, f"runs network client {prog}")
            elif prog == "base64" and any(a in ("-d", "--decode", "-D") for a in args):
                decode_seen = True
                add(Capability.OBFUSCATION, Severity.MEDIUM, "decodes base64 data")
            elif prog in ("env", "printenv", "set", "export") and not args:
                add(
                    Capability.ENV,
                    Severity.MEDIUM,
                    f"dumps the environment with {prog}",
                    secret=True,
                )
            elif prog == "eval":
                add(Capability.DYNAMIC_CODE, Severity.MEDIUM, "uses shell eval")
            if prog in INTERPRETERS:
                if fetch_seen:
                    add(
                        Capability.NETWORK,
                        Severity.CRITICAL,
                        f"pipes downloaded content into {prog}",
                        rule="SW310",
                        title="download-and-execute in install script",
                    )
                elif decode_seen:
                    add(
                        Capability.OBFUSCATION,
                        Severity.CRITICAL,
                        f"pipes decoded data into {prog}",
                        title="obfuscated code execution in build/install code",
                    )
                hits.extend(_interpreter(prog, args, hook, read_file, add))
    return hits


def _interpreter(
    prog: str,
    args: list[str],
    hook: str,
    read_file: ReadFile | None,
    add: Callable[..., None],
) -> list[Hit]:
    inline = _INLINE_FLAGS.get(prog, ())
    for k, arg in enumerate(args):
        if arg in inline:
            code = args[k + 1] if k + 1 < len(args) else ""
            add(Capability.DYNAMIC_CODE, Severity.MEDIUM, f"runs inline {prog} code")
            if prog == "node" and code:
                return [_relabel(h, hook, "inline") for h in review_js(code)]
            return []
    if prog == "node" and read_file is not None:
        script = next((a for a in args if not a.startswith("-")), None)
        if script is not None:
            source = read_file(script) or read_file(script + ".js")
            if source is not None:
                return [_relabel(h, hook, script) for h in review_js(source)]
    return []


def _relabel(hit: Hit, hook: str, where: str) -> Hit:
    hit.detail = f"{hook} runs {where}: {hit.detail}"
    hit.evidence = {"script": hook, **hit.evidence}
    if where != "inline":
        hit.path = where
    return hit
