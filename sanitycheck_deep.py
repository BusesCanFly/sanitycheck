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
  entropy-blob      a long, genuinely high-entropy base64 literal (payload)

Online resolver (--resolve; safe, no code execution):
  transitive-ioc-pkg   a transitive dependency is a known-malicious package
  transitive-typosquat a transitive dependency typosquats a popular package
  dep-confusion        a declared dependency does not exist on public PyPI
  pypi-fresh           a declared dependency was published in the last 30 days

Usage:  sanitycheck_deep.py [--resolve] [--iocs FILE] <root-dir>
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

def scan_python(path: Path, root: Path) -> None:
    text = read_text(path)
    if text is None:
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


def scan_unicode(path: Path, root: Path) -> None:
    text = read_text(path)
    if text is None:
        return
    # a leading UTF-8 BOM (U+FEFF) is legitimate and extremely common on Windows
    # files; strip it so it is not mistaken for a hidden zero-width character.
    if text.startswith("﻿"):
        text = text[1:]
    rp = relpath(path, root)
    for i, ch in enumerate(text):
        if ch in BIDI_CHARS:
            line = text.count("\n", 0, i) + 1
            emit("HIGH", "trojan-source", rp, line,
                 f"Unicode bidirectional control U+{ord(ch):04X} in source - "
                 f"'Trojan Source' attack: code renders differently to a human "
                 f"reviewer than it executes")
            return
    for i, ch in enumerate(text):
        if ch in INVISIBLE_CHARS:
            line = text.count("\n", 0, i) + 1
            emit("MED", "invisible-unicode", rp, line,
                 f"Invisible/zero-width character U+{ord(ch):04X} in source - "
                 f"can hide code or homoglyph an identifier")
            return


def scan_blobs(path: Path, root: Path) -> None:
    text = read_text(path)
    if text is None:
        return
    rp = relpath(path, root)
    for m in B64_RE.finditer(text):
        blob = m.group(0)
        ent = shannon_entropy(blob)
        if ent < 4.2:
            continue
        line = text.count("\n", 0, m.start()) + 1
        window = text[max(0, m.start() - 120): m.start() + len(blob) + 120]
        near = re.search(r"\b(exec|eval|compile|marshal|loads|__import__|"
                         r"b64decode)\b", window)
        emit("HIGH" if near else "MED", "entropy-blob", rp, line,
             f"High-entropy base64 blob (len={len(blob)}, entropy={ent:.1f})"
             + (" feeding exec/decode nearby" if near else ""))
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

def load_malicious_pkgs(iocs_path: str | None) -> dict[str, str]:
    """Read `pkg<TAB>name<TAB>note` lines from the IOC db."""
    out: dict[str, str] = {}
    if not iocs_path:
        return out
    try:
        with open(iocs_path, encoding="utf-8", errors="replace") as fh:
            for raw in fh:
                if raw.startswith("#") or "\t" not in raw:
                    continue
                parts = raw.rstrip("\n").split("\t")
                if len(parts) >= 2 and parts[0].strip() == "pkg":
                    out[strip_pkg(parts[1])] = parts[2] if len(parts) > 2 else ""
    except OSError:
        pass
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


def resolve(root: Path, malicious: dict[str, str]) -> None:
    top = []
    seen_top: set[str] = set()
    for pkg, _rp in collect_deps(root):
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


def fetch_packages(ecosystem: str, dest: str, names: list[str]) -> int:
    fetched = 0
    for name in names[:FETCH_MAX_PKGS]:
        url = None
        if ecosystem == "pypi":
            meta = pypi_metadata(name)
            if not meta or meta.get("__http__"):
                if meta and meta.get("__http__") == 404:
                    emit("HIGH", "pkg-missing", name, 0,
                         f"package '{name}' does not exist on PyPI - possible "
                         f"dependency-confusion / typo")
                continue
            urls = meta.get("urls") or []
            pick = next((u for u in urls if u.get("packagetype") == "bdist_wheel"), None) \
                or next((u for u in urls if u.get("packagetype") == "sdist"), None)
            url = pick.get("url") if pick else None
        elif ecosystem == "npm":
            meta = npm_metadata(name)
            if not meta or meta.get("__http__"):
                if meta and meta.get("__http__") == 404:
                    emit("HIGH", "pkg-missing", name, 0,
                         f"package '{name}' does not exist on the npm registry - "
                         f"possible dependency-confusion / typo")
                continue
            latest = (meta.get("dist-tags") or {}).get("latest") or ""
            ver = (meta.get("versions") or {}).get(latest, {})
            url = ((ver.get("dist") or {}).get("tarball"))
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
            if url.endswith((".whl", ".zip", ".egg")):
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
    ap.add_argument("--iocs", default=None, help="IOC db for known-malicious names")
    ap.add_argument("--fetch", choices=["pypi", "npm"],
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
        return 0

    if not args.root:
        return 0
    root = Path(args.root).resolve()
    if not root.is_dir():
        return 0  # stay silent so the shell tool is unaffected

    for path in iter_files(root):
        ext = path.suffix.lower()
        if ext in (".py", ".pyw", ".pyx"):
            scan_python(path, root)
        if ext in TEXT_EXTS:
            scan_blobs(path, root)
        if ext in UNICODE_EXTS:
            scan_unicode(path, root)
    scan_typosquat(root)

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
