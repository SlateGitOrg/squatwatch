"""Token-level review of JavaScript run by npm lifecycle scripts.

This is deliberately *not* a JavaScript parser. A small tokenizer separates
comments, string/template literals, regex literals, identifiers and punctuation
so that patterns are matched on code tokens only (a ``"child_process"`` inside a
comment is ignored). Patterns then look at short token windows:

* ``require("mod")``, ``import ... from "mod"``, ``import("mod")`` — module
  capabilities (``child_process`` = process, ``http``/``https``/``net``/... = network);
* ``fetch(``, ``XMLHttpRequest``, ``WebSocket`` — network;
* ``process.env``, ``process.env.NAME``, ``process.env["NAME"]`` — environment;
* ``eval(``, ``Function(``, ``vm.runIn*`` — dynamic code, escalated when the
  argument tokens contain ``Buffer.from(..., "base64")``/``atob(``;
* string literals naming credential files.

Limitations (documented): no data flow, no aliasing beyond direct ``require``
bindings, minified/obfuscated code is only flagged through its decoding calls.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass

from squatwatch.hooks.common import SECRET_ENV, Capability, Hit, mentions_sensitive_path
from squatwatch.models import Severity

NETWORK_MODULES = frozenset(
    {
        "http",
        "https",
        "http2",
        "net",
        "tls",
        "dgram",
        "dns",
        "node:http",
        "node:https",
        "node:net",
        "node:tls",
        "node:dgram",
        "node:dns",
        "axios",
        "node-fetch",
        "got",
        "request",
        "undici",
        "ws",
    }
)
PROCESS_MODULES = frozenset({"child_process", "node:child_process"})
PROCESS_FUNCS = frozenset(
    {"exec", "execSync", "spawn", "spawnSync", "execFile", "execFileSync", "fork"}
)
_KEYWORDS_BEFORE_REGEX = frozenset(
    {
        "return",
        "typeof",
        "instanceof",
        "in",
        "of",
        "new",
        "delete",
        "void",
        "throw",
        "case",
        "do",
        "else",
    }
)
_IDENT = re.compile(r"[A-Za-z_$][\w$]*")
_NUMBER = re.compile(r"\d[\w.]*")


@dataclass(frozen=True, slots=True)
class Token:
    """A JavaScript token: kind is ident, string, number, regex or punct."""

    kind: str
    text: str
    line: int


def tokenize(source: str) -> list[Token]:
    """Split JavaScript into tokens, dropping comments and whitespace."""
    out: list[Token] = []
    i, n, line = 0, len(source), 1
    while i < n:
        ch = source[i]
        if ch == "\n":
            line += 1
            i += 1
        elif ch.isspace():
            i += 1
        elif source.startswith("//", i):
            j = source.find("\n", i)
            i = n if j == -1 else j
        elif source.startswith("/*", i):
            j = source.find("*/", i + 2)
            end = n if j == -1 else j + 2
            line += source.count("\n", i, end)
            i = end
        elif ch in "'\"`":
            j = i + 1
            while j < n and source[j] != ch:
                j += 2 if source[j] == "\\" else 1
            text = source[i + 1 : min(j, n)]
            out.append(Token("string", text, line))
            line += source.count("\n", i, min(j + 1, n))
            i = j + 1
        elif ch == "/" and _regex_allowed(out):
            j = i + 1
            in_class = False
            while j < n and source[j] != "\n":
                c = source[j]
                if c == "\\":
                    j += 2
                    continue
                if c == "[":
                    in_class = True
                elif c == "]":
                    in_class = False
                elif c == "/" and not in_class:
                    break
                j += 1
            j += 1
            while j < n and source[j].isalpha():
                j += 1
            out.append(Token("regex", source[i:j], line))
            i = j
        elif m := _IDENT.match(source, i):
            out.append(Token("ident", m.group(), line))
            i = m.end()
        elif m := _NUMBER.match(source, i):
            out.append(Token("number", m.group(), line))
            i = m.end()
        else:
            out.append(Token("punct", ch, line))
            i += 1
    return out


def _regex_allowed(prev: list[Token]) -> bool:
    if not prev:
        return True
    last = prev[-1]
    if last.kind == "ident":
        return last.text in _KEYWORDS_BEFORE_REGEX
    if last.kind in ("string", "number", "regex"):
        return False
    return last.text not in ")]}"


def _is(tokens: list[Token], i: int, kind: str, text: str | None = None) -> bool:
    return (
        0 <= i < len(tokens) and tokens[i].kind == kind and (text is None or tokens[i].text == text)
    )


def _call_args(tokens: list[Token], open_idx: int) -> list[Token]:
    """Tokens between the parenthesis at ``open_idx`` and its match."""
    depth = 0
    for j in range(open_idx, len(tokens)):
        t = tokens[j]
        if t.kind == "punct" and t.text == "(":
            depth += 1
        elif t.kind == "punct" and t.text == ")":
            depth -= 1
            if depth == 0:
                return tokens[open_idx + 1 : j]
    return tokens[open_idx + 1 :]


def _has_decode(tokens: list[Token]) -> bool:
    for k, t in enumerate(tokens):
        if t.kind == "ident" and t.text == "atob":
            return True
        if t.kind == "string" and t.text in ("base64", "hex") and k > 0:
            return True
    return False


def review_js(source: str, *, context: str = "lifecycle-script") -> list[Hit]:
    """Review JavaScript source run by an install hook."""
    toks = tokenize(source)
    hits: list[Hit] = []
    modules: dict[str, str] = {}  # local binding -> module

    def add(cap: Capability, sev: Severity, tok: Token, detail: str, **kw: object) -> None:
        secret = bool(kw.pop("secret", False))
        title = kw.pop("title", None)
        hits.append(
            Hit(
                cap,
                sev,
                tok.line,
                detail,
                context,
                dict(kw),
                secret=secret,
                title=title if isinstance(title, str) else None,
            )
        )

    for i, t in enumerate(toks):
        if t.kind == "string":
            frag = mentions_sensitive_path(t.text)
            if frag is not None:
                add(
                    Capability.SENSITIVE_FILE,
                    Severity.HIGH,
                    t,
                    f"references credential path {frag!r}",
                )
            continue
        if t.kind != "ident":
            continue
        module = _module_ref(toks, i)
        if module is not None:
            binding = _binding_for(toks, i)
            if binding:
                modules[binding] = module
            if module in PROCESS_MODULES:
                add(Capability.PROCESS, Severity.MEDIUM, t, f"loads {module}", module=module)
            elif module in NETWORK_MODULES:
                add(
                    Capability.NETWORK,
                    Severity.HIGH,
                    t,
                    f"loads network module {module}",
                    module=module,
                )
            continue
        if t.text in ("fetch", "XMLHttpRequest", "WebSocket") and _is(toks, i + 1, "punct", "("):
            add(Capability.NETWORK, Severity.HIGH, t, f"calls {t.text}()")
        elif (
            t.text == "process"
            and _is(toks, i + 1, "punct", ".")
            and _is(toks, i + 2, "ident", "env")
        ):
            _env_access(toks, i, add)
        elif t.text in ("eval", "Function") and _is(toks, i + 1, "punct", "("):
            args = _call_args(toks, i + 1)
            if _has_decode(args):
                add(
                    Capability.OBFUSCATION,
                    Severity.CRITICAL,
                    t,
                    f"{t.text}() runs code decoded from an embedded payload",
                    title="obfuscated code execution in build/install code",
                )
            else:
                add(Capability.DYNAMIC_CODE, Severity.MEDIUM, t, f"calls {t.text}()")
        elif t.text.startswith("runIn") and t.text.endswith("Context"):
            add(Capability.DYNAMIC_CODE, Severity.MEDIUM, t, f"calls vm.{t.text}()")
        elif t.text in PROCESS_FUNCS and _is(toks, i + 1, "punct", "("):
            owner = toks[i - 2].text if i >= 2 and _is(toks, i - 1, "punct", ".") else t.text
            if modules.get(owner) in PROCESS_MODULES or modules.get(t.text) in PROCESS_MODULES:
                add(Capability.PROCESS, Severity.MEDIUM, t, f"runs a process via {t.text}()")
        elif t.text == "atob" or (
            t.text == "from"
            and i >= 2
            and _is(toks, i - 2, "ident", "Buffer")
            and _has_decode(_call_args(toks, i + 1))
        ):
            add(Capability.OBFUSCATION, Severity.MEDIUM, t, "decodes embedded data")
    return hits


def _module_ref(toks: list[Token], i: int) -> str | None:
    """Module named by ``require("m")``/``import("m")`` at i, or ``from "m"``."""
    t = toks[i]
    if (
        t.text in ("require", "import")
        and _is(toks, i + 1, "punct", "(")
        and _is(toks, i + 2, "string")
    ):
        return toks[i + 2].text
    if t.text == "from" and _is(toks, i + 1, "string"):
        return toks[i + 1].text
    return None


def _binding_for(toks: list[Token], i: int) -> str | None:
    """``const cp = require(...)`` -> ``cp``; ``import cp from "m"`` -> ``cp``."""
    if toks[i].text == "from":
        j = i - 1
        while j >= 0 and not _is(toks, j, "ident", "import"):
            j -= 1
        return toks[j + 1].text if _is(toks, j + 1, "ident") else None
    if i >= 2 and _is(toks, i - 1, "punct", "=") and _is(toks, i - 2, "ident"):
        return toks[i - 2].text
    return None


def _env_access(toks: list[Token], i: int, add: Callable[..., None]) -> None:
    t = toks[i]
    var: str | None = None
    if (_is(toks, i + 3, "punct", ".") and _is(toks, i + 4, "ident")) or (
        _is(toks, i + 3, "punct", "[") and _is(toks, i + 4, "string")
    ):
        var = toks[i + 4].text
    if var is None:
        add(
            Capability.ENV,
            Severity.MEDIUM,
            t,
            "uses the whole process.env object",
            secret=True,
        )
    elif SECRET_ENV.search(var):
        add(
            Capability.ENV,
            Severity.HIGH,
            t,
            f"reads credential-like environment variable {var!r}",
            secret=True,
            variable=var,
        )
    else:
        add(Capability.ENV, Severity.LOW, t, f"reads environment variable {var!r}", variable=var)
