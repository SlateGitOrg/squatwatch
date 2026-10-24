"""Static review of Python build code (``setup.py``, in-tree PEP 517 backends,
``.pth`` start-up files). Nothing is imported or executed.

The analyser works in three passes over the ``ast``:

1. **Imports** — an alias table maps local names to qualified names
   (``import subprocess as sp``, ``from os import system``), so calls resolve to
   dotted names such as ``subprocess.run`` or ``urllib.request.urlopen``.
2. **Reachability** — module-level statements run whenever the build imports the
   file. Methods of classes deriving from setuptools/distutils commands
   (``install``, ``develop``, ``egg_info``...) run at install time. In an in-tree
   PEP 517 backend the hook functions (``build_wheel``, ``build_sdist``,
   ``build_editable``, ``get_requires_for_build_*``, ``prepare_metadata_for_build_*``)
   are entry points too, because the build frontend calls them by contract;
   functions bound to a hook name (``build_wheel = _impl``) count as hooks.
   Functions called (by plain name) from any of these, transitively, are
   reachable too. Anything else is "unreferenced" and its findings are reported
   one severity lower.
3. **Capabilities** — each call/attribute is matched against catalogues of
   network, process, dynamic-code, environment, credential-path and decoding
   APIs. ``exec``/``eval`` over decoded data is escalated to critical.
"""

from __future__ import annotations

import ast
import re
from collections.abc import Iterable

from squatwatch.hooks.common import (
    SECRET_ENV,
    Capability,
    Hit,
    mentions_sensitive_path,
)
from squatwatch.models import Severity

NETWORK_MODULES: tuple[str, ...] = (
    "requests",
    "httpx",
    "urllib3",
    "aiohttp",
    "socket",
    "http.client",
    "ftplib",
    "smtplib",
    "telnetlib",
    "paramiko",
    "pycurl",
    "websocket",
    "dns.resolver",
)
NETWORK_CALLS = frozenset(
    {
        "urllib.request.urlopen",
        "urllib.request.urlretrieve",
        "urllib.request.build_opener",
        "urllib.urlopen",
        "urllib.urlretrieve",
        "urllib2.urlopen",
        "urllib2.build_opener",
    }
)
PROCESS_MODULES: tuple[str, ...] = ("subprocess", "pty", "commands")
PROCESS_CALLS = frozenset(
    {
        "os.system",
        "os.popen",
        "os.startfile",
        "asyncio.create_subprocess_shell",
        "asyncio.create_subprocess_exec",
    }
)
PROCESS_PREFIXES: tuple[str, ...] = ("os.exec", "os.spawn", "os.posix_spawn")
DYNAMIC_CALLS = frozenset(
    {
        "exec",
        "eval",
        "compile",
        "marshal.loads",
        "pickle.loads",
        "types.CodeType",
        "types.FunctionType",
    }
)
DECODE_CALLS = frozenset(
    {
        "base64.b64decode",
        "base64.b32decode",
        "base64.b16decode",
        "base64.b85decode",
        "base64.a85decode",
        "base64.decodebytes",
        "base64.decodestring",
        "base64.urlsafe_b64decode",
        "binascii.a2b_base64",
        "binascii.unhexlify",
        "binascii.a2b_hex",
        "bytes.fromhex",
        "zlib.decompress",
        "bz2.decompress",
        "lzma.decompress",
        "gzip.decompress",
        "codecs.decode",
    }
)
BULK_ENV_SINKS = frozenset(
    {"dict", "str", "repr", "list", "json.dumps", "json.dump", "pickle.dumps", "print"}
)
COMMAND_BASES = frozenset(
    {
        "install",
        "develop",
        "egg_info",
        "build",
        "build_py",
        "build_ext",
        "build_clib",
        "sdist",
        "bdist_wheel",
        "bdist_egg",
        "install_lib",
        "install_scripts",
        "Command",
    }
)
#: PEP 517 (and PEP 660 editable) hooks a build frontend calls on a backend.
BACKEND_HOOKS = frozenset(
    {
        "build_wheel",
        "build_sdist",
        "build_editable",
        "get_requires_for_build_wheel",
        "get_requires_for_build_sdist",
        "get_requires_for_build_editable",
        "prepare_metadata_for_build_wheel",
        "prepare_metadata_for_build_editable",
    }
)
_BLOB = re.compile(r"^[A-Za-z0-9+/=_\-\s]{256,}$")


def _dotted(node: ast.expr, aliases: dict[str, str]) -> str | None:
    """Qualified dotted name of an expression, resolving import aliases."""
    if isinstance(node, ast.Name):
        return aliases.get(node.id, node.id)
    if isinstance(node, ast.Attribute):
        base = _dotted(node.value, aliases)
        return f"{base}.{node.attr}" if base else None
    if isinstance(node, ast.Call):
        func = _dotted(node.func, aliases)
        if func in ("__import__", "importlib.import_module") and node.args:
            arg = node.args[0]
            if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                return arg.value
        return f"{func}()" if func else None
    return None


def _imports(tree: ast.Module) -> dict[str, str]:
    aliases: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                if a.asname:
                    aliases[a.asname] = a.name
                else:
                    top = a.name.split(".", 1)[0]
                    aliases[top] = top
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            for a in node.names:
                aliases[a.asname or a.name] = f"{node.module}.{a.name}"
    return aliases


def _calls_in(nodes: Iterable[ast.AST]) -> set[str]:
    """Plain function names called anywhere inside ``nodes``."""
    names: set[str] = set()
    for root in nodes:
        for node in ast.walk(root):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                names.add(node.func.id)
            elif (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and isinstance(node.func.value, ast.Name)
                and node.func.value.id == "self"
            ):
                names.add(node.func.attr)
    return names


def _backend_hooks(tree: ast.Module) -> set[str]:
    """Names of functions a build frontend calls on this backend module: the PEP
    517/660 hook names plus any function bound to one at module level
    (``build_wheel = _impl``)."""
    names = set(BACKEND_HOOKS)
    for stmt in tree.body:
        if isinstance(stmt, ast.Assign) and isinstance(stmt.value, ast.Name):
            if any(isinstance(t, ast.Name) and t.id in BACKEND_HOOKS for t in stmt.targets):
                names.add(stmt.value.id)
        elif (
            isinstance(stmt, ast.AnnAssign)
            and isinstance(stmt.target, ast.Name)
            and stmt.target.id in BACKEND_HOOKS
            and isinstance(stmt.value, ast.Name)
        ):
            names.add(stmt.value.id)
    return names


class _Reachability:
    """Computes the execution context of every function body in a module."""

    def __init__(self, tree: ast.Module, aliases: dict[str, str], entry_context: str) -> None:
        self.functions: dict[str, ast.FunctionDef | ast.AsyncFunctionDef] = {}
        self.context: dict[ast.AST, str] = {}
        self.hook_classes: list[str] = []
        top_level: list[ast.stmt] = []
        hook_methods: list[ast.AST] = []
        for stmt in tree.body:
            if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
                self.functions[stmt.name] = stmt
            elif isinstance(stmt, ast.ClassDef):
                is_hook = any(self._is_command_base(b, aliases) for b in stmt.bases)
                if is_hook:
                    self.hook_classes.append(stmt.name)
                for item in stmt.body:
                    if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        if is_hook:
                            self.context[item] = "install-hook"
                            hook_methods.append(item)
                        self.functions.setdefault(item.name, item)
                    else:
                        top_level.append(item)
            else:
                top_level.append(stmt)
        self._propagate(_calls_in(top_level), entry_context)
        if entry_context == "build-backend":
            self._propagate(_backend_hooks(tree), "build-backend")
        self._propagate(_calls_in(hook_methods), "install-hook")

    @staticmethod
    def _is_command_base(base: ast.expr, aliases: dict[str, str]) -> bool:
        name = _dotted(base, aliases) or ""
        return name.rsplit(".", 1)[-1] in COMMAND_BASES and (
            "setuptools" in name or "distutils" in name or "." not in name
        )

    def _propagate(self, roots: set[str], context: str) -> None:
        pending = list(roots)
        while pending:
            name = pending.pop()
            fn = self.functions.get(name)
            if fn is None or fn in self.context:
                continue
            self.context[fn] = context
            pending.extend(_calls_in([fn]))

    def of(self, fn: ast.AST, enclosing: str | None) -> str:
        """Context of ``fn``; nested definitions inherit their enclosing context."""
        if fn in self.context:
            return self.context[fn]
        return enclosing if enclosing is not None else "unreferenced"


class _Visitor(ast.NodeVisitor):
    def __init__(self, aliases: dict[str, str], reach: _Reachability, entry_context: str) -> None:
        self.aliases = aliases
        self.reach = reach
        self.stack: list[str] = [entry_context]
        self.hits: list[Hit] = []

    # -- context tracking
    def _enter_function(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        enclosing = self.ctx if len(self.stack) > 1 else None
        self.stack.append(self.reach.of(node, enclosing))
        self.generic_visit(node)
        self.stack.pop()

    visit_FunctionDef = _enter_function  # noqa: N815 - ast.NodeVisitor naming
    visit_AsyncFunctionDef = _enter_function  # noqa: N815

    @property
    def ctx(self) -> str:
        return self.stack[-1]

    def hit(
        self,
        cap: Capability,
        severity: Severity,
        node: ast.AST,
        detail: str,
        **kwargs: object,
    ) -> None:
        secret = bool(kwargs.pop("secret", False))
        rule = kwargs.pop("rule", None)
        title = kwargs.pop("title", None)
        self.hits.append(
            Hit(
                capability=cap,
                severity=severity,
                line=getattr(node, "lineno", None),
                detail=detail,
                context=self.ctx,
                evidence=dict(kwargs),
                secret=secret,
                rule=rule if isinstance(rule, str) else None,
                title=title if isinstance(title, str) else None,
            )
        )

    # -- calls
    def visit_Call(self, node: ast.Call) -> None:
        name = _dotted(node.func, self.aliases)
        if name:
            self._classify_call(node, name)
        self.generic_visit(node)

    def _classify_call(self, node: ast.Call, name: str) -> None:
        if name in NETWORK_CALLS or _has_prefix(name, NETWORK_MODULES):
            self.hit(Capability.NETWORK, Severity.HIGH, node, f"calls {name}()", call=name)
        elif (
            name in PROCESS_CALLS
            or _has_prefix(name, PROCESS_MODULES)
            or name.startswith(PROCESS_PREFIXES)
        ):
            self.hit(
                Capability.PROCESS, Severity.MEDIUM, node, f"runs a process via {name}()", call=name
            )
        elif name in DYNAMIC_CALLS:
            self._dynamic(node, name)
        elif name in ("__import__", "importlib.import_module"):
            self.hit(
                Capability.DYNAMIC_CODE,
                Severity.MEDIUM,
                node,
                f"imports a module chosen at run time via {name}()",
                call=name,
            )
        elif name in DECODE_CALLS and self._is_decoding(node, name):
            self.hit(
                Capability.OBFUSCATION,
                Severity.MEDIUM,
                node,
                f"decodes data with {name}()",
                call=name,
            )
        elif name in ("os.getenv", "os.environ.get", "os.getenvb"):
            self._env_key(node, name)
        elif name in BULK_ENV_SINKS and any(
            _dotted(a, self.aliases) == "os.environ" for a in node.args
        ):
            self.hit(
                Capability.ENV,
                Severity.MEDIUM,
                node,
                f"copies the whole environment into {name}()",
                secret=True,
            )

    def _dynamic(self, node: ast.Call, name: str) -> None:
        payload = node.args[0] if node.args else None
        if payload is not None and _contains_decode(payload, self.aliases):
            self.hit(
                Capability.OBFUSCATION,
                Severity.CRITICAL,
                node,
                f"{name}() runs code produced by decoding an embedded payload",
                call=name,
                title="obfuscated code execution in build/install code",
            )
            return
        if payload is not None and _reads_file(payload, self.aliases):
            self.hit(
                Capability.DYNAMIC_CODE,
                Severity.LOW,
                node,
                f"{name}() runs the contents of a file (common for version files)",
                call=name,
            )
            return
        self.hit(Capability.DYNAMIC_CODE, Severity.MEDIUM, node, f"calls {name}()", call=name)

    @staticmethod
    def _is_decoding(node: ast.Call, name: str) -> bool:
        if name != "codecs.decode":
            return True
        codec = node.args[1] if len(node.args) > 1 else None
        if codec is None:
            codec = next((k.value for k in node.keywords if k.arg == "encoding"), None)
        return (
            isinstance(codec, ast.Constant)
            and isinstance(codec.value, str)
            and codec.value.lower().replace("-", "_")
            in {"rot13", "rot_13", "hex", "base64", "zlib", "bz2"}
        )

    def _env_key(self, node: ast.Call, name: str) -> None:
        key = node.args[0] if node.args else None
        if isinstance(key, ast.Constant) and isinstance(key.value, str):
            self._env_named(node, key.value, name)
        else:
            self.hit(
                Capability.ENV,
                Severity.LOW,
                node,
                f"reads a computed environment variable via {name}",
            )

    def _env_named(self, node: ast.AST, var: str, how: str) -> None:
        if SECRET_ENV.search(var):
            self.hit(
                Capability.ENV,
                Severity.HIGH,
                node,
                f"reads credential-like environment variable {var!r} via {how}",
                secret=True,
                variable=var,
            )
        else:
            self.hit(
                Capability.ENV,
                Severity.LOW,
                node,
                f"reads environment variable {var!r}",
                variable=var,
            )

    # -- os.environ used other than via .get()
    def visit_Subscript(self, node: ast.Subscript) -> None:
        if _dotted(node.value, self.aliases) == "os.environ":
            key = node.slice
            if isinstance(key, ast.Constant) and isinstance(key.value, str):
                self._env_named(node, key.value, "os.environ[...]")
            else:
                self.hit(
                    Capability.ENV, Severity.LOW, node, "reads a computed environment variable"
                )
            self.visit(node.slice)
            return
        self.generic_visit(node)

    def visit_Attribute(self, node: ast.Attribute) -> None:
        if _dotted(node.value, self.aliases) == "os.environ" and node.attr in {
            "items",
            "keys",
            "values",
        }:
            self.hit(
                Capability.ENV,
                Severity.MEDIUM,
                node,
                f"enumerates the whole environment (os.environ.{node.attr})",
                secret=True,
            )
        self.generic_visit(node)

    def visit_Constant(self, node: ast.Constant) -> None:
        if isinstance(node.value, str):
            frag = mentions_sensitive_path(node.value)
            if frag is not None:
                self.hit(
                    Capability.SENSITIVE_FILE,
                    Severity.HIGH,
                    node,
                    f"references credential path fragment {frag!r}",
                    fragment=frag,
                )
            elif _BLOB.match(node.value):
                self.hit(
                    Capability.OBFUSCATION,
                    Severity.MEDIUM,
                    node,
                    f"embeds a {len(node.value)}-character encoded-looking string",
                )


def _has_prefix(name: str, modules: tuple[str, ...]) -> bool:
    return any(name == m or name.startswith(m + ".") for m in modules)


def _contains_decode(node: ast.AST, aliases: dict[str, str]) -> bool:
    for sub in ast.walk(node):
        if isinstance(sub, ast.Call):
            name = _dotted(sub.func, aliases) or ""
            if name in DECODE_CALLS or name.endswith(".decompress"):
                return True
        if isinstance(sub, ast.Constant) and isinstance(sub.value, str) and _BLOB.match(sub.value):
            return True
    return False


def _reads_file(node: ast.AST, aliases: dict[str, str]) -> bool:
    for sub in ast.walk(node):
        if isinstance(sub, ast.Call):
            name = _dotted(sub.func, aliases) or ""
            if name in ("open", "io.open", "codecs.open") or name.endswith(".read_text"):
                return True
    return False


def _cmdclass_keys(tree: ast.Module) -> list[str]:
    keys: list[str] = []
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.keyword)
            and node.arg == "cmdclass"
            and isinstance(node.value, ast.Dict)
        ):
            keys.extend(str(k.value) for k in node.value.keys if isinstance(k, ast.Constant))
    return keys


class PythonReview:
    """Result of reviewing one Python source file."""

    def __init__(
        self,
        hits: list[Hit],
        hook_classes: list[str],
        cmdclass: list[str],
        syntax_error: str | None,
    ) -> None:
        self.hits = hits
        self.hook_classes = hook_classes
        self.cmdclass = cmdclass
        self.syntax_error = syntax_error


def review_python(source: str, path: str, *, entry_context: str = "module") -> PythonReview:
    """Review Python ``source``; ``entry_context`` is the context of module-level code."""
    try:
        tree = ast.parse(source, filename=path)
    except SyntaxError as exc:
        return PythonReview([], [], [], f"line {exc.lineno or '?'}: {exc.msg}")
    aliases = _imports(tree)
    reach = _Reachability(tree, aliases, entry_context)
    visitor = _Visitor(aliases, reach, entry_context)
    visitor.visit(tree)
    return PythonReview(visitor.hits, reach.hook_classes, _cmdclass_keys(tree), None)
