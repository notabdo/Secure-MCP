"""Dependency manifest parsers for Python, JS/TS, Rust, and Go."""

import json
import re
import tomllib
from pathlib import Path

from .config import SKIP_DIRS


def parse_python_deps(path: Path) -> list[str]:
    """Parse pyproject.toml for project dependencies."""
    data = tomllib.loads(path.read_text(encoding="utf-8"))
    return data.get("project", {}).get("dependencies", [])


def parse_npm_deps(path: Path) -> list[str]:
    """Parse package.json for npm dependencies."""
    data = json.loads(path.read_text(encoding="utf-8"))
    deps = {**data.get("dependencies", {}), **data.get("devDependencies", {})}
    return [f"{k}@{v}" for k, v in deps.items()]


def parse_cargo_deps(path: Path) -> list[str]:
    """Parse Cargo.toml for Rust dependencies."""
    data = tomllib.loads(path.read_text(encoding="utf-8"))
    out = []
    for name, spec in data.get("dependencies", {}).items():
        ver = spec if isinstance(spec, str) else spec.get("version", "?")
        out.append(f"{name}@{ver}")
    return out


def parse_go_deps(path: Path) -> list[str]:
    """Parse go.mod for Go module dependencies."""
    text = path.read_text(encoding="utf-8")
    return [
        f"{m}@{v}"
        for m, v in re.findall(
            r'^\s*([a-zA-Z0-9_.\-/]+)\s+(v[\d][^\s]*)',
            text,
            re.MULTILINE,
        )
    ]


DEP_PARSERS = {
    "pyproject.toml": ("python", parse_python_deps),
    "package.json": ("javascript", parse_npm_deps),
    "Cargo.toml": ("rust", parse_cargo_deps),
    "go.mod": ("go", parse_go_deps),
}


def scan_dependencies(root: Path, report):
    """Scan the project root for dependency manifests and populate the report."""
    for fname, (lang, parser) in DEP_PARSERS.items():
        for manifest in root.rglob(fname):
            if any(part in SKIP_DIRS for part in manifest.parts):
                continue
            try:
                deps = parser(manifest)
            except Exception:
                continue
            if deps:
                report.languages.add(lang)
            for d in deps:
                report.dependencies.append(d)
                report.add(
                    "info",
                    "dependency",
                    str(manifest),
                    0,
                    f"[{lang}] depends on: {d}",
                )
