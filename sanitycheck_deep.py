#!/usr/bin/env python3
"""
sanitycheck deep-pass helper - optional Python analysis for sanitycheck.

The main tool is shell (grep/find) so its core runs offline with zero
dependencies. This helper adds precise checks that regex cannot do well, and is
invoked only when python3 is available. It NEVER imports, installs, or executes
the target: it parses Python with `ast` (which does not run code) and, for the
optional resolver, reads PyPI's JSON metadata over HTTPS (never building or
installing a package -- building an sdist would run setup.py, the very thing we
are defending against).

It emits one finding per line as TAB-separated fields for the shell tool to fold
into its findings list:

    SEV<TAB>TAG<TAB>RELPATH<TAB>LINE<TAB>MESSAGE

SEV is CRIT | HIGH | MED | LOW. RELPATH is relative to the scanned root (or
"declared-dependencies" for dependency-graph findings).

Offline checks (always):
  ast-install-exec  exec/eval at import time in setup.py (runs on `pip install`)
  ast-decode-exec   decoded/decompressed data passed straight to exec/eval
  typosquat         a declared dep one edit from a popular package
  go-typosquat      a go.mod require that is a near-miss for a popular module
  entropy-blob      a long, genuinely high-entropy base64 literal (payload)

Online resolver (--resolve; safe, no code execution):
  transitive-ioc-pkg   a transitive dependency is a known-malicious package
  transitive-typosquat a transitive dependency typosquats a popular package
  dep-confusion        a declared dependency does not exist on public PyPI
  pypi-fresh           a declared dependency was published in the last 30 days

Fetch mode (--fetch; download + extract only, still no code execution) pulls
named packages from PyPI, npm, crates.io or the Go module proxy so the shell can
scan their real contents. With --resolve it also walks the fetched package's own
dependency graph, which is how `pip install <dropper>` reaches a payload that
only appears one level down.

Usage:  sanitycheck_deep.py [--resolve] [--iocs FILE]... <root-dir>
        sanitycheck_deep.py --fetch pypi|npm|go|crates --dest DIR NAME...
"""
from __future__ import annotations

import argparse
import ast
import json
import math
import os
import re
import sys
import time
import urllib.request
import urllib.parse
from pathlib import Path

SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__",
             ".mypy_cache", ".pytest_cache", ".tox", "dist", "build"}
TEXT_EXTS = {".py", ".pyw", ".pyx", ".txt", ".cfg", ".toml", ".json", ".md"}
MAX_BYTES = 2 * 1024 * 1024

POPULAR = {
    "requests", "urllib3", "numpy", "pandas", "cryptography", "pyyaml", "yaml",
    "flask", "django", "scipy", "pillow", "setuptools", "wheel", "pip",
    "beautifulsoup4", "bs4", "lxml", "paramiko", "scapy", "pwntools", "colorama",
    "click", "rich", "tqdm", "aiohttp", "httpx", "pycryptodome", "psutil",
    "certifi", "idna", "packaging", "impacket", "dnspython", "pyopenssl",
}

DECODE_FUNCS = ("b64decode", "b85decode", "b32decode", "fromhex", "loads",
                "decompress", "decode")
EXEC_FUNCS = {"exec", "eval"}
B64_RE = re.compile(r"[A-Za-z0-9+/]{200,}={0,2}")

# "Trojan Source" (CVE-2021-42574) bidirectional control characters: they make
# source render one way to a human reviewer and execute another way. Any of
# these in code is a strong tell.
BIDI_CHARS = {"‪", "‫", "‬", "‭", "‮",
              "⁦", "⁧", "⁨", "⁩", "؜"}
# Zero-width / invisible characters used to hide or homoglyph identifiers
# (e.g. the 2025 npm 'os-info-checker-es6' / Glassworm technique).
INVISIBLE_CHARS = {"​", "‌", "‍", "⁠", "﻿",
                   "­", "᠎", "⁡", "⁢", "⁣"}
UNICODE_EXTS = {".py", ".pyw", ".pyx", ".js", ".mjs", ".cjs", ".ts", ".jsx",
                ".tsx", ".c", ".h", ".cpp", ".cc", ".cs", ".go", ".rs", ".java",
                ".rb", ".php", ".sh", ".bash", ".ps1", ".pl"}

# resolver bounds (keep the metadata walk cheap, terminating, and responsive
# enough to run inside a shell hook). RESOLVE_BUDGET caps total wall-clock so a
# huge dependency graph or a slow PyPI host can never hang the terminal.
RESOLVE_MAX_NODES = 200
RESOLVE_MAX_DEPTH = 4
RESOLVE_TIMEOUT = 5
RESOLVE_BUDGET = float(os.environ.get("SANITYCHECK_RESOLVE_BUDGET", "12"))


# --------------------------------------------------------------------------- #

def emit(sev: str, tag: str, relpath: str, line: int, msg: str) -> None:
    msg = msg.replace("\t", " ").replace("\n", " ")
    print(f"{sev}\t{tag}\t{relpath}\t{line}\t{msg}")


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts: dict[str, int] = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def osa_distance(a: str, b: str) -> int:
    """Optimal String Alignment distance: Levenshtein plus adjacent
    transposition as a single edit, so 'reqeusts' is distance 1 from
    'requests' (a common typosquat shape)."""
    if a == b:
        return 0
    if not a or not b:
        return len(a) + len(b)
    la, lb = len(a), len(b)
    d = [[0] * (lb + 1) for _ in range(la + 1)]
    for i in range(la + 1):
        d[i][0] = i
    for j in range(lb + 1):
        d[0][j] = j
    for i in range(1, la + 1):
        for j in range(1, lb + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            d[i][j] = min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + cost)
            if i > 1 and j > 1 and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]:
                d[i][j] = min(d[i][j], d[i - 2][j - 2] + 1)
    return d[la][lb]


def normalize_pkg(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name.strip().lower())


def strip_pkg(name: str) -> str:
    # drop all separators so a known-bad "skytext" also matches "sky-text"
    return re.sub(r"[-_.]+", "", name.strip().lower())


def is_typosquat(norm: str) -> str | None:
    if norm in POPULAR:
        return None
    for pop in POPULAR:
        if 0 < osa_distance(norm, pop) <= 1 and abs(len(norm) - len(pop)) <= 1:
            return pop
    return None


def read_text(path: Path) -> str | None:
    try:
        with path.open("rb") as fh:
            data = fh.read(MAX_BYTES)
    except OSError:
        return None
    return data.decode("utf-8", errors="replace")


def iter_files(root: Path):
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for name in filenames:
            yield Path(dirpath) / name


def relpath(path: Path, root: Path) -> str:
    try:
        return str(path.relative_to(root))
    except ValueError:
        return str(path)


def call_name(call: ast.Call) -> str | None:
    f = call.func
    if isinstance(f, ast.Name):
        return f.id
    if isinstance(f, ast.Attribute):
        return f.attr
    return None


def contains_decode_then_exec(call: ast.Call) -> bool:
    for arg in ast.walk(call):
        if isinstance(arg, ast.Call) and call_name(arg) in DECODE_FUNCS:
            return True
    return False


# --------------------------------------------------------------------------- #
# Offline AST checks
# --------------------------------------------------------------------------- #

# Both AST checks below end at `call_name(node) in EXEC_FUNCS`, so a file with no
# exec/eval call cannot produce a finding no matter what its tree looks like.
# Parsing it anyway was the single most expensive thing this helper did: on a
# 6.5k-file checkout, ast.parse cost 2.3s and ast.walk 7.3s across 2076 .py
# files, of which 50 contain such a call. The substring test comes first because
# it is ~20x cheaper than the regex and rejects most files outright.
_EXEC_CALL_RE = re.compile(r"\b(exec|eval)\s*\(")


def has_exec_call(text: str) -> bool:
    return ("exec" in text or "eval" in text) and bool(_EXEC_CALL_RE.search(text))


def scan_python(path: Path, root: Path, text: str) -> None:
    if not has_exec_call(text):
        return
    rp = relpath(path, root)
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return

    if path.name == "setup.py":
        for node in getattr(tree, "body", []):
            call = None
            if isinstance(node, ast.Expr) and isinstance(node.value, ast.Call):
                call = node.value
            elif isinstance(node, ast.Assign) and isinstance(node.value, ast.Call):
                call = node.value
            if call and call_name(call) in EXEC_FUNCS:
                emit("HIGH", "ast-install-exec", rp, call.lineno,
                     "exec/eval at module level in setup.py - runs during "
                     "`pip install`, before you ever run the exploit")

    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and call_name(node) in EXEC_FUNCS:
            if contains_decode_then_exec(node):
                emit("HIGH", "ast-decode-exec", rp, node.lineno,
                     "Decoded/decompressed data passed straight to exec/eval - "
                     "unpacks data and runs it")


# Character-class regexes rather than a Python loop over every character: the two
# `for i, ch in enumerate(text)` loops this replaces cost 2.4s on a 6.5k-file
# checkout, and found nothing that a regex does not.
_BIDI_RE = re.compile("[" + "".join(BIDI_CHARS) + "]")
_INVISIBLE_RE = re.compile("[" + "".join(INVISIBLE_CHARS) + "]")

# Average line length past which a file is treated as minified/generated.
_MINIFIED_AVG_LINE = 500


def looks_minified(text: str) -> bool:
    return len(text) > 2000 and len(text) / (text.count("\n") + 1) > _MINIFIED_AVG_LINE


def scan_unicode(path: Path, root: Path, text: str) -> None:
    # Both of these attacks target a human reading the file. Two kinds of file are
    # never read that way and legitimately full of the characters involved:
    #
    #  - minified bundles. CodeMirror emits U+200B deliberately; playwright ships
    #    two copies of it, which is where three real checkouts picked up a MED.
    #  - translation catalogues, whose whole content is other people's scripts.
    #    Qt Linguist files use .ts, the same extension as TypeScript, so the
    #    extension list alone cannot tell them apart - sniff the XML preamble.
    if looks_minified(text):
        return
    if path.suffix.lower() == ".ts" and "<" in text[:200]:
        head = text.lstrip()[:200]
        if head.startswith("<?xml") or "<!DOCTYPE TS" in head:
            return
    # a leading UTF-8 BOM (U+FEFF) is legitimate and extremely common on Windows
    # files; strip it so it is not mistaken for a hidden zero-width character.
    if text.startswith("﻿"):
        text = text[1:]
    rp = relpath(path, root)
    m = _BIDI_RE.search(text)
    if m:
        emit("HIGH", "trojan-source", rp, text.count("\n", 0, m.start()) + 1,
             f"Unicode bidirectional control U+{ord(m.group(0)):04X} in source - "
             f"'Trojan Source' attack: code renders differently to a human "
             f"reviewer than it executes")
        return
    m = _INVISIBLE_RE.search(text)
    if m:
        emit("MED", "invisible-unicode", rp, text.count("\n", 0, m.start()) + 1,
             f"Invisible/zero-width character U+{ord(m.group(0)):04X} in source - "
             f"can hide code or homoglyph an identifier")


# The finding requires an execution/decode primitive within 120 characters of the
# blob, so a file that never mentions one anywhere cannot produce it. Checking
# that first is exact, and skips the scan on most files.
_NEAR_RE = re.compile(r"\b(exec|eval|compile|marshal|loads|__import__|b64decode)\b")


def scan_blobs(path: Path, root: Path, text: str) -> None:
    if not _NEAR_RE.search(text):
        return
    rp = relpath(path, root)
    for m in B64_RE.finditer(text):
        blob = m.group(0)
        ent = shannon_entropy(blob)
        if ent < 4.2:
            continue
        line = text.count("\n", 0, m.start()) + 1
        window = text[max(0, m.start() - 120): m.start() + len(blob) + 120]
        near = _NEAR_RE.search(window)
        # A long base64 literal on its own is data, not behaviour - certificates,
        # icons, test vectors and licence files are full of them. It only says
        # something once it is being fed to an execution or decode primitive.
        if not near:
            continue
        emit("HIGH", "entropy-blob", rp, line,
             f"High-entropy base64 blob (len={len(blob)}, entropy={ent:.1f})"
             " feeding exec/decode nearby")
        break


# --------------------------------------------------------------------------- #
# Declared-dependency collection (shared by typosquat + resolver)
# --------------------------------------------------------------------------- #

_REQ_LINE = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)")
# a requirement string inside a dependency array: name possibly followed by an
# extras bracket, version specifier, or environment marker.
_DEP_TOKEN = re.compile(r'["\']([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:[<>=!~;\[(].*?)?["\']')
# key = "..."  form used by [tool.poetry.dependencies] TOML tables
_TOML_KEY = re.compile(r'^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*=')
# a dependency *array* assignment: install_requires=[...], dependencies = [...],
# requires = [...]. We only read names from inside these, never from arbitrary
# quoted strings (which would pick up the package's own name, URLs, cmdclass
# keys like "install", classifiers, etc. -> false dependency-confusion hits).
_DEP_ARRAY = re.compile(
    r'(?:install_requires|dependencies|requires|setup_requires|tests_require)'
    r'\s*=\s*\[(.*?)\]', re.S)

_STOPWORDS = {"python", "python_requires", "install", "develop", "test"}


def _names_from_arrays(text: str) -> list[str]:
    out: list[str] = []
    for m in _DEP_ARRAY.finditer(text):
        for tm in _DEP_TOKEN.finditer(m.group(1)):
            cand = tm.group(1)
            if cand.lower() not in _STOPWORDS:
                out.append(cand)
    return out


def collect_deps(root: Path) -> list[tuple[str, str]]:
    deps: list[tuple[str, str]] = []
    for path in iter_files(root):
        name = path.name.lower()
        rp = relpath(path, root)
        if name.startswith("requirements") and name.endswith(".txt"):
            text = read_text(path)
            if text:
                for raw in text.splitlines():
                    s = raw.strip()
                    if not s or s.startswith("#") or s.startswith("-"):
                        continue
                    mm = _REQ_LINE.match(s)
                    if mm:
                        deps.append((mm.group(1), rp))
        elif name in ("setup.py", "setup.cfg"):
            text = read_text(path)
            if text:
                for cand in _names_from_arrays(text):
                    deps.append((cand, rp))
        elif name == "pyproject.toml":
            text = read_text(path)
            if text:
                # PEP 621 / setuptools: dependencies = [ "..." ] arrays
                for cand in _names_from_arrays(text):
                    deps.append((cand, rp))
                # Poetry: [tool.poetry.dependencies] table of  name = "..."
                in_poetry = False
                for raw in text.splitlines():
                    s = raw.strip()
                    if s.startswith("["):
                        in_poetry = s.startswith("[tool.poetry") and "dependencies" in s
                        continue
                    if in_poetry:
                        km = _TOML_KEY.match(raw)
                        if km and km.group(1).lower() not in _STOPWORDS:
                            deps.append((km.group(1), rp))
    return deps


# --------------------------------------------------------------------------- #
# Go module typosquatting
#
# The dominant real-world attack on Go is a near-miss module path, because Go has
# no central registry of names - anyone can publish any path they control. Two
# shapes account for the known cases:
#   boltdb-go/bolt      vs boltdb/bolt        - decoration added to the owner
#   shopsprint/decimal  vs shopspring/decimal - one character changed
# so both a decoration-stripped comparison and an edit-distance comparison are
# needed; either alone misses half of them.
# --------------------------------------------------------------------------- #

POPULAR_GO = {
    "github.com/stretchr/testify", "github.com/sirupsen/logrus",
    "github.com/spf13/cobra", "github.com/spf13/viper", "github.com/spf13/pflag",
    "github.com/spf13/afero", "github.com/pkg/errors", "github.com/gorilla/mux",
    "github.com/gorilla/websocket", "github.com/gin-gonic/gin",
    "github.com/go-sql-driver/mysql", "github.com/lib/pq",
    "github.com/google/uuid", "github.com/google/go-cmp",
    "github.com/mattn/go-sqlite3", "github.com/mattn/go-isatty",
    "github.com/fatih/color", "github.com/boltdb/bolt", "go.etcd.io/bbolt",
    "github.com/shopspring/decimal", "github.com/json-iterator/go",
    "github.com/prometheus/client_golang", "github.com/aws/aws-sdk-go",
    "github.com/aws/aws-sdk-go-v2", "gopkg.in/yaml.v2", "gopkg.in/yaml.v3",
    "golang.org/x/crypto", "golang.org/x/net", "golang.org/x/sys",
    "golang.org/x/text", "golang.org/x/sync", "golang.org/x/time",
    "golang.org/x/tools", "golang.org/x/oauth2", "golang.org/x/term",
    "github.com/davecgh/go-spew", "github.com/pmezard/go-difflib",
    "github.com/cespare/xxhash", "github.com/klauspost/compress",
    "github.com/urfave/cli", "github.com/hashicorp/go-multierror",
    "github.com/hashicorp/hcl", "github.com/rs/zerolog", "go.uber.org/zap",
    "github.com/pelletier/go-toml", "github.com/BurntSushi/toml",
    "github.com/mitchellh/mapstructure", "github.com/miekg/dns",
    "github.com/go-chi/chi", "github.com/labstack/echo",
    "github.com/valyala/fasthttp", "github.com/redis/go-redis",
    "go.mongodb.org/mongo-driver", "gorm.io/gorm",
    "github.com/golang-jwt/jwt", "github.com/gofrs/uuid",
    "github.com/tidwall/gjson", "github.com/olekukonko/tablewriter",
    "github.com/schollz/progressbar", "github.com/briandowns/spinner",
    "github.com/charmbracelet/bubbletea", "github.com/charmbracelet/lipgloss",
    "google.golang.org/grpc", "google.golang.org/protobuf",
}

# host/owner/repo, followed by a version - matches inside a require ( ) block too
_GO_MOD_REQ = re.compile(
    r"^\s*([a-zA-Z0-9][\w.\-]*\.[a-zA-Z]{2,}(?:/[\w.\-~]+)+)\s+v[0-9]", re.M)
_GO_MOD_MODULE = re.compile(r"^\s*module\s+(\S+)", re.M)


def go_norm(path: str) -> str:
    """Strip the decorations a typosquat adds: separators, a /vN major suffix,
    and a leading or trailing 'go' on any segment. boltdb-go/bolt and
    boltdb/bolt both reduce to boltdb/bolt."""
    p = re.sub(r"/v[0-9]+$", "", path.lower())
    out = []
    for seg in p.split("/"):
        s = re.sub(r"[-_.]", "", seg)
        if s not in ("go",):                       # keep a segment that IS "go"
            stripped = re.sub(r"^go|go$", "", s)
            if stripped:
                s = stripped
        out.append(s)
    return "/".join(out)


_POPULAR_GO_NORM = {go_norm(p): p for p in POPULAR_GO}


def go_owner(path: str) -> str:
    """host/owner - the part a typosquat has to differ in to impersonate anyone."""
    return "/".join(path.lower().split("/")[:2])


def go_typosquat(path: str) -> str | None:
    if path in POPULAR_GO:
        return None
    # A /vN suffix is Go's major-version convention, not a near-miss:
    # github.com/cespare/xxhash/v2 IS github.com/cespare/xxhash. Checked first,
    # because stripping it is exactly what makes the two collide below.
    base = re.sub(r"/v[0-9]+$", "", path)
    if base in POPULAR_GO:
        return None
    owner = go_owner(path)
    norm = go_norm(path)
    hit = _POPULAR_GO_NORM.get(norm)
    if hit and hit != path and go_owner(hit) != owner:
        return hit
    low = path.lower()
    for pop in POPULAR_GO:
        pl = pop.lower()
        # Same owner is not impersonation - tidwall publishes both gjson and
        # sjson, one edit apart. Both known attacks (boltdb-go, shopsprint)
        # differ in the owner segment.
        if go_owner(pop) == owner:
            continue
        # only compare paths of similar shape, or every short path matches
        if abs(len(pl) - len(low)) <= 1 and 0 < osa_distance(low, pl) <= 1:
            return pop
    return None


def collect_go_deps(root: Path) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    for path in iter_files(root):
        if path.name != "go.mod":
            continue
        text = read_text(path)
        if not text:
            continue
        rp = relpath(path, root)
        own = _GO_MOD_MODULE.search(text)
        own_path = own.group(1) if own else ""
        for m in _GO_MOD_REQ.finditer(text):
            dep = m.group(1)
            if dep and dep != own_path:
                out.append((dep, rp))
    return out


def scan_go_typosquat(root: Path) -> None:
    seen: set[str] = set()
    for dep, rp in collect_go_deps(root):
        if dep in seen:
            continue
        seen.add(dep)
        pop = go_typosquat(dep)
        if pop:
            emit("HIGH", "go-typosquat", rp, 0,
                 f"Module '{dep}' is a near-miss for popular module '{pop}' - "
                 f"Go has no central name registry, so this is how boltdb-go/bolt "
                 f"and shopsprint/decimal were delivered")


def scan_typosquat(root: Path) -> None:
    seen: set[str] = set()
    for pkg, rp in collect_deps(root):
        norm = normalize_pkg(pkg)
        if norm in seen:
            continue
        seen.add(norm)
        pop = is_typosquat(norm)
        if pop:
            emit("HIGH", "typosquat", rp, 0,
                 f"Dependency '{pkg}' is one edit from popular package "
                 f"'{pop}' - possible typosquat")


# --------------------------------------------------------------------------- #
# Online resolver - safe transitive dependency graph over PyPI JSON metadata
# --------------------------------------------------------------------------- #

def load_malicious_pkgs(iocs_paths: str | list[str] | None) -> dict[str, str]:
    """Read `pkg<TAB>name<TAB>note` lines from every IOC db given.

    Takes a list because --ioc is repeatable on the shell side. It used to take
    one path and the shell only ever passed the built-in database, so a user's
    own `--ioc` file was matched by the shell's own name check but invisible to
    the transitive resolver - the one place it would have caught a name that is
    not in the manifest.
    """
    out: dict[str, str] = {}
    if not iocs_paths:
        return out
    if isinstance(iocs_paths, str):
        iocs_paths = [iocs_paths]
    for path in iocs_paths:
        if not path:
            continue
        try:
            with open(path, encoding="utf-8", errors="replace") as fh:
                for raw in fh:
                    if raw.startswith("#") or "\t" not in raw:
                        continue
                    parts = raw.rstrip("\n").split("\t")
                    if len(parts) >= 2 and parts[0].strip() == "pkg":
                        out[strip_pkg(parts[1])] = parts[2] if len(parts) > 2 else ""
        except OSError:
            continue
    return out


def pypi_metadata(name: str) -> dict | None:
    url = f"https://pypi.org/pypi/{name}/json"
    req = urllib.request.Request(url, headers={"User-Agent": "sanitycheck"})
    try:
        with urllib.request.urlopen(req, timeout=RESOLVE_TIMEOUT) as resp:
            if resp.status != 200:
                return None
            return json.loads(resp.read().decode("utf-8", errors="replace"))
    except urllib.error.HTTPError as e:
        return {"__http__": e.code}
    except Exception:
        return None


_DIST_NAME = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)")


def requires_names(meta: dict) -> list[str]:
    out: list[str] = []
    for spec in (meta.get("info", {}).get("requires_dist") or []):
        # skip extras/optional markers: "foo (>=1) ; extra == 'bar'"
        if ";" in spec and "extra" in spec.split(";", 1)[1]:
            continue
        m = _DIST_NAME.match(spec)
        if m:
            out.append(m.group(1))
    return out


def newest_upload_days(meta: dict) -> int | None:
    import datetime
    times = []
    for rels in meta.get("releases", {}).values():
        for f in rels:
            t = f.get("upload_time_iso_8601") or f.get("upload_time")
            if t:
                times.append(t[:10])
    if not times:
        return None
    try:
        newest = max(times)
        d = datetime.date.fromisoformat(newest)
        return (datetime.date.today() - d).days
    except Exception:
        return None


def resolve(root: Path, malicious: dict[str, str], seed: list[str] | None = None) -> None:
    """Walk the PyPI metadata graph from the declared dependencies of `root`, or
    from `seed` when the caller already knows the names (a `pip install <name>`,
    where nothing is on disk to read a manifest from). Seeded or not, the IOC and
    typosquat checks only fire below depth 0 - the top-level names are already
    matched by the shell engine."""
    top = []
    seen_top: set[str] = set()
    for pkg in (seed if seed is not None else [p for p, _rp in collect_deps(root)]):
        n = normalize_pkg(pkg)
        if n not in seen_top:
            seen_top.add(n)
            top.append(pkg)

    visited: set[str] = set()
    queue: list[tuple[str, int, str]] = [(p, 0, p) for p in top]  # name, depth, path
    nodes = 0
    deadline = time.monotonic() + RESOLVE_BUDGET

    while queue and nodes < RESOLVE_MAX_NODES:
        if time.monotonic() > deadline:
            emit("LOW", "resolve-truncated", "declared-dependencies", 0,
                 f"transitive resolution stopped after {RESOLVE_BUDGET:.0f}s "
                 f"({nodes} packages checked); some transitive deps were not "
                 f"resolved - re-run without a hook, or raise "
                 f"SANITYCHECK_RESOLVE_BUDGET")
            break
        name, depth, path = queue.pop(0)
        norm = normalize_pkg(name)
        if norm in visited:
            continue
        visited.add(norm)
        nodes += 1

        # match transitive nodes against IOCs + typosquat. Direct (declared)
        # deps are already matched by the shell engine, so only report the
        # transitive ones here to avoid a duplicate ioc-pkg finding.
        sp = strip_pkg(name)
        if sp in malicious and depth > 0:
            emit("CRIT", "transitive-ioc-pkg", "declared-dependencies", 0,
                 f"Transitively pulls known-malicious package '{name}' via "
                 f"{path} - {malicious[sp] or 'IOC'}")
        pop = is_typosquat(norm)
        if pop and depth > 0:
            emit("HIGH", "transitive-typosquat", "declared-dependencies", 0,
                 f"Transitive dependency '{name}' (via {path}) typosquats '{pop}'")

        meta = pypi_metadata(name)
        if meta is None:
            continue
        if meta.get("__http__") == 404:
            if depth == 0:
                emit("HIGH", "dep-confusion", "declared-dependencies", 0,
                     f"Declared dependency '{name}' does not exist on public "
                     f"PyPI - possible dependency-confusion / private name")
            continue

        if depth == 0:
            days = newest_upload_days(meta)
            if days is not None and 0 <= days <= 30:
                emit("MED", "pypi-fresh", "declared-dependencies", 0,
                     f"Dependency '{name}' last published {days} day(s) ago - "
                     f"freshly created packages near a CVE drop are suspicious")

        if depth < RESOLVE_MAX_DEPTH:
            for child in requires_names(meta):
                if normalize_pkg(child) not in visited:
                    queue.append((child, depth + 1, f"{path} -> {child}"))


# --------------------------------------------------------------------------- #
# Fetch a registry package's artifact and extract it (NO code execution - just
# download + untar/unzip) so the caller can statically scan the real contents.
# Everything is bounded and extraction is hardened against path traversal / zip
# bombs, because these archives are untrusted.
# --------------------------------------------------------------------------- #

FETCH_MAX_PKGS = 6
FETCH_ARTIFACT_MAX = 30 * 1024 * 1024      # per-artifact download cap
EXTRACT_MAX_FILES = 4000
EXTRACT_MAX_BYTES = 100 * 1024 * 1024

# Where a PEP 440 spec stops being a name: an operator, an extras bracket, an
# environment marker, or whitespace.
_PEP440_SPLIT = re.compile(r"[<>=!~;\[\s]")
_PEP440_PIN = re.compile(r"==\s*([A-Za-z0-9._+!-]+)")


def split_spec(spec: str, ecosystem: str) -> tuple[str, str]:
    """Split a package argument as typed into (name, pinned version).

    The install hooks pass through whatever the user wrote, so this receives
    `requests==2.31.0`, `requests[socks]`, `lodash@4.17.21` and
    `github.com/x/y@v1.2.3`. Those used to go into the registry URL whole, which
    404s - and a 404 is reported as "does not exist on the registry - possible
    dependency-confusion", so pinning a version invented a HIGH finding against
    an ordinary install. Returns ("", "") for anything that is not a registry
    name (VCS URL, local path, option), which the caller skips.
    """
    s = spec.strip()
    if not s or s.startswith("-") or "://" in s:
        return "", ""
    if s.startswith((".", "/", "git+", "file:")):
        return "", ""
    ver = ""
    if ecosystem == "pypi":
        m = _PEP440_SPLIT.search(s)
        if m:
            pin = _PEP440_PIN.search(s[m.start():])
            ver = pin.group(1) if pin else ""
            s = s[:m.start()]
    else:
        # npm "@scope/name@version" and go "module/path@version": the version is
        # after the LAST @, while a leading @ is an npm scope, not a separator.
        lead, body = ("@", s[1:]) if s.startswith("@") else ("", s)
        if "@" in body:
            body, ver = body.rsplit("@", 1)
        s = lead + body
    return s.rstrip("/"), ver


def http_get_bytes(url: str, maxsize: int) -> bytes | None:
    req = urllib.request.Request(url, headers={"User-Agent": "sanitycheck"})
    try:
        with urllib.request.urlopen(req, timeout=RESOLVE_TIMEOUT) as resp:
            if getattr(resp, "status", 200) != 200:
                return None
            data = resp.read(maxsize + 1)
            return None if len(data) > maxsize else data
    except Exception:
        return None


def npm_metadata(name: str) -> dict | None:
    url = "https://registry.npmjs.org/" + urllib.parse.quote(name, safe="@")
    req = urllib.request.Request(url, headers={"User-Agent": "sanitycheck"})
    try:
        with urllib.request.urlopen(req, timeout=RESOLVE_TIMEOUT) as resp:
            if resp.status != 200:
                return None
            return json.loads(resp.read().decode("utf-8", errors="replace"))
    except urllib.error.HTTPError as e:
        return {"__http__": e.code}
    except Exception:
        return None


def _within(dest: str, member: str) -> bool:
    if member.startswith("/") or member.startswith("\\"):
        return False
    if ".." in member.replace("\\", "/").split("/"):
        return False
    d = os.path.realpath(dest)
    t = os.path.realpath(os.path.join(dest, member))
    return t == d or t.startswith(d + os.sep)


def _extract_tar(data: bytes, dest: str) -> None:
    import io
    import tarfile
    files = total = 0
    with tarfile.open(fileobj=io.BytesIO(data)) as tf:
        for m in tf.getmembers():
            if files >= EXTRACT_MAX_FILES or total >= EXTRACT_MAX_BYTES:
                break
            if m.issym() or m.islnk() or not (m.isfile() or m.isdir()):
                continue                       # skip links/devices (traversal)
            if not _within(dest, m.name):
                continue
            if m.isfile():
                total += max(m.size, 0)
            try:
                tf.extract(m, dest)
            except Exception:
                continue
            files += 1


def _extract_zip(data: bytes, dest: str) -> None:
    import io
    import zipfile
    files = total = 0
    with zipfile.ZipFile(io.BytesIO(data)) as zf:
        for info in zf.infolist():
            if files >= EXTRACT_MAX_FILES or total >= EXTRACT_MAX_BYTES:
                break
            if not _within(dest, info.filename):
                continue
            total += info.file_size
            try:
                zf.extract(info, dest)
            except Exception:
                continue
            files += 1


def http_get_json(url: str) -> dict | None:
    req = urllib.request.Request(url, headers={"User-Agent": "sanitycheck"})
    try:
        with urllib.request.urlopen(req, timeout=RESOLVE_TIMEOUT) as resp:
            if resp.status != 200:
                return None
            return json.loads(resp.read().decode("utf-8", errors="replace"))
    except urllib.error.HTTPError as e:
        return {"__http__": e.code}
    except Exception:
        return None


def go_escape(path: str) -> str:
    """Module proxy paths are case-encoded: an uppercase letter becomes !<lower>,
    so github.com/BurntSushi/toml is fetched as github.com/!burnt!sushi/toml."""
    return re.sub(r"[A-Z]", lambda m: "!" + m.group(0).lower(), path)


def go_latest(module: str) -> dict | None:
    esc = urllib.parse.quote(go_escape(module), safe="/!~.-_")
    return http_get_json(f"https://proxy.golang.org/{esc}/@latest")


def fetch_packages(ecosystem: str, dest: str, names: list[str]) -> int:
    fetched = 0
    if len(names) > FETCH_MAX_PKGS:
        skipped = names[FETCH_MAX_PKGS:]
        emit("LOW", "pkg-uninspected", "requested-packages", 0,
             f"only the first {FETCH_MAX_PKGS} packages were content-scanned; "
             f"not inspected: {', '.join(skipped)}")
    for spec in names[:FETCH_MAX_PKGS]:
        name, want_ver = split_spec(spec, ecosystem)
        if not name:
            continue                 # URL / local path / flag: nothing to look up
        url = None
        if ecosystem == "pypi":
            meta = pypi_metadata(name)
            if not meta or meta.get("__http__"):
                if meta and meta.get("__http__") == 404:
                    emit("HIGH", "pkg-missing", name, 0,
                         f"package '{name}' does not exist on PyPI - possible "
                         f"dependency-confusion / typo")
                continue
            # A pinned version is what will actually be installed, so it is what
            # gets scanned; `urls` is whatever PyPI considers current.
            urls = (meta.get("releases") or {}).get(want_ver) if want_ver else None
            if not urls:
                urls = meta.get("urls") or []
            pick = next((u for u in urls if u.get("packagetype") == "bdist_wheel"), None) \
                or next((u for u in urls if u.get("packagetype") == "sdist"), None)
            url = pick.get("url") if pick else None
        elif ecosystem == "go":
            # `go install ./cmd/foo` style paths never reach here (the hook sends
            # those as a directory scan), but a bare name with no dot in its
            # first element is a stdlib path and has nothing to fetch.
            if "." not in name.split("/")[0]:
                continue
            ver = want_ver
            if not ver:
                meta = go_latest(name)
                if not meta or meta.get("__http__"):
                    if meta and meta.get("__http__") in (404, 410):
                        emit("HIGH", "pkg-missing", name, 0,
                             f"module '{name}' is not on the Go module proxy - "
                             f"possible dependency-confusion / typo")
                    continue
                ver = meta.get("Version") or ""
            if not ver:
                continue
            esc = urllib.parse.quote(go_escape(name), safe="/!~.-_")
            url = f"https://proxy.golang.org/{esc}/@v/{go_escape(ver)}.zip"
        elif ecosystem == "crates":
            # `cargo install` compiles what it fetches, and build.rs runs during
            # that compile - the same install-time execution as setup.py.
            ver = want_ver
            if not ver:
                meta = http_get_json(f"https://crates.io/api/v1/crates/{urllib.parse.quote(name, safe='')}")
                if not meta or meta.get("__http__"):
                    if meta and meta.get("__http__") == 404:
                        emit("HIGH", "pkg-missing", name, 0,
                             f"crate '{name}' does not exist on crates.io - "
                             f"possible dependency-confusion / typo")
                    continue
                ver = ((meta.get("crate") or {}).get("max_stable_version")
                       or (meta.get("crate") or {}).get("newest_version") or "")
            if not ver:
                continue
            url = (f"https://crates.io/api/v1/crates/"
                   f"{urllib.parse.quote(name, safe='')}/{urllib.parse.quote(ver, safe='')}/download")
        elif ecosystem == "npm":
            meta = npm_metadata(name)
            if not meta or meta.get("__http__"):
                if meta and meta.get("__http__") == 404:
                    emit("HIGH", "pkg-missing", name, 0,
                         f"package '{name}' does not exist on the npm registry - "
                         f"possible dependency-confusion / typo")
                continue
            versions = meta.get("versions") or {}
            pick_ver = want_ver if want_ver in versions else \
                (meta.get("dist-tags") or {}).get("latest") or ""
            url = ((versions.get(pick_ver, {}).get("dist") or {}).get("tarball"))
        if not url:
            continue
        data = http_get_bytes(url, FETCH_ARTIFACT_MAX)
        if data is None:
            emit("LOW", "pkg-uninspected", name, 0,
                 f"could not fetch '{name}' for inspection (too large or "
                 f"unreachable) - install was not content-scanned")
            continue
        outdir = os.path.join(dest, re.sub(r"[^A-Za-z0-9._@-]", "_", name))
        os.makedirs(outdir, exist_ok=True)
        try:
            if url.endswith((".whl", ".zip", ".egg")) or ecosystem == "go":
                _extract_zip(data, outdir)
            else:
                _extract_tar(data, outdir)
            fetched += 1
        except Exception:
            continue
    return fetched


# --------------------------------------------------------------------------- #

def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(prog="sanitycheck_deep.py", add_help=True)
    ap.add_argument("root", nargs="?")
    ap.add_argument("--resolve", action="store_true",
                    help="also walk the transitive PyPI dependency graph (network)")
    ap.add_argument("--iocs", action="append", default=None,
                    help="IOC db for known-malicious names (repeatable)")
    ap.add_argument("--fetch", choices=["pypi", "npm", "go", "crates"],
                    help="download+extract named packages into --dest for scanning")
    ap.add_argument("--dest", help="destination dir for --fetch")
    ap.add_argument("names", nargs="*", help="package names for --fetch")
    args = ap.parse_args(argv[1:])

    # fetch mode: download + extract registry packages (no execution) so the
    # shell can scan their real contents. argparse puts the first positional in
    # `root`, so reassemble all positionals as the package-name list.
    if args.fetch:
        names = ([args.root] if args.root else []) + (args.names or [])
        if args.dest and names:
            fetch_packages(args.fetch, args.dest, names)
            # `pip install <dropper>` fetches and scans the dropper, but the
            # ChocoPoC shape is a clean-looking package whose *dependency* is the
            # payload - frint -> skytext. That walk only ran for repos, so the
            # case the tool is named after was missed on the install path.
            # PyPI-only, because the resolver is PyPI JSON metadata.
            if args.resolve and args.fetch == "pypi":
                seed = [n for n, _v in (split_spec(s, "pypi") for s in names) if n]
                if seed:
                    resolve(Path(args.dest), load_malicious_pkgs(args.iocs), seed=seed)
        return 0

    if not args.root:
        return 0
    root = Path(args.root).resolve()
    if not root.is_dir():
        return 0  # stay silent so the shell tool is unaffected

    # One read per file, shared by every scanner that wants it. Each used to open
    # and decode the file itself, so a .py went through read_text three times.
    # Reading every text file in a 6.5k-file checkout costs 0.44s, so the I/O was
    # never the problem - doing it three times over was.
    for path in iter_files(root):
        ext = path.suffix.lower()
        want_py = ext in (".py", ".pyw", ".pyx")
        want_blob = ext in TEXT_EXTS
        want_uni = ext in UNICODE_EXTS
        if not (want_py or want_blob or want_uni):
            continue
        text = read_text(path)
        if text is None:
            continue
        if want_py:
            scan_python(path, root, text)
        if want_blob:
            scan_blobs(path, root, text)
        if want_uni:
            scan_unicode(path, root, text)
    scan_typosquat(root)
    scan_go_typosquat(root)

    if args.resolve:
        resolve(root, load_malicious_pkgs(args.iocs))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv))
    except BrokenPipeError:
        sys.exit(0)
    except KeyboardInterrupt:
        sys.exit(0)
