# security-space

Security scanner for MCP (Model Context Protocol) servers. It combines
**dependency manifest analysis**, **AST-based static analysis** (via
tree-sitter), and an **optional Gemini AI review layer** to surface risky
patterns in MCP server codebases before you run them.

> **Disclaimer:** Static analysis provides a *probabilistic* assessment based
> on pattern matching, not certainty. Findings indicate the *likelihood* of a
> problem. Enable AI analysis (`--ai-analyze`) and/or review findings manually
> for higher confidence.

## Features

- **Multi-language AST scanning** for Python, JavaScript, TypeScript, Rust, and Go.
- **Dependency manifest parsing** for `pyproject.toml`, `package.json`, `Cargo.toml`, and `go.mod`.
- **Rich context extraction** — for every finding it captures the offending line, the enclosing function/class, the call arguments (with taint hints), and relevant imports.
- **Alias resolution** — tracks `import ... as`, `require`, `use`, and Go import aliases so dangerous calls are matched against their fully-qualified names.
- **Optional Gemini AI taint analysis** — performs data-flow reasoning to confirm exploitability and reduce false positives.
- **Multiple output formats** — text, JSON, Markdown, and a styled HTML report.
- **CI-friendly exit codes** — fail the build on critical/warning findings or a minimum risk score.
- **Clean, emoji-free output** suitable for professional and CI environments.

## Installation

Requires **Python 3.10+**.

```bash
# From the repository root
pip install -e .

# Core runtime dependency
pip install tree-sitter-languages

# Optional: required only for AI analysis
pip install google-genai
# (requests is used as a fallback transport if google-genai is unavailable)
```

## Usage

```bash
# Basic scan of a local directory
python -m mcp_scan ./my-mcp-server

# Scan a remote Git repository (auto-cloned to a temp dir)
python -m mcp_scan https://github.com/owner/repo

# With AI validation (strongly recommended)
python -m mcp_scan ./my-mcp-server --ai-analyze --gemini-api-key YOUR_KEY

# HTML report written to a file
python -m mcp_scan ./my-mcp-server -f html -o report.html

# JSON output for downstream tooling
python -m mcp_scan ./my-mcp-server -f json -o report.json

# CI gate: fail on critical findings
python -m mcp_scan ./my-mcp-server --fail-on critical

# CI gate: fail if risk score >= 40
python -m mcp_scan ./my-mcp-server --min-score 40
```



### Command-line options

| Option | Description |
| --- | --- |
| `target` | Local path or Git URL of the MCP server to scan. |
| `-f, --format` | Report format: `text` (default), `json`, `markdown`, `html`. |
| `-o, --output` | Write the report to a file instead of stdout. |
| `--fail-on` | Exit code `1` if findings of this severity or higher exist: `critical` (default), `warning`, `none`. |
| `--min-score` | Exit code `1` if the risk score is `>=` this number. |
| `--ai-analyze` | Enable Gemini AI analysis of findings (one-shot request). |
| `--gemini-api-key` | Gemini API key (required when `--ai-analyze` is set). |
| `--gemini-model` | Gemini model id (default: `gemini-3.1-flash-lite`). |

## Supported languages

| Language | Extensions | Dependency file |
| --- | --- | --- |
| Python | `.py` | `pyproject.toml` |
| JavaScript | `.js`, `.jsx` | `package.json` |
| TypeScript | `.ts`, `.tsx` | `package.json` |
| Rust | `.rs` | `Cargo.toml` |
| Go | `.go` | `go.mod` |

Directories skipped automatically: `node_modules`, `target`, `dist`, `build`,
`.git`, `__pycache__`, `venv`, `.venv`. Files whose names contain `test` are
also skipped.

## Detection categories

The scanner flags calls and constructs across these categories (severity in
parentheses):

- **Code execution** (`critical`/`warning`) — `eval`, `exec`, `compile`,
  `os.system`, `subprocess.*`, `vm.runIn*`, `child_process.exec*`,
  `Command::new`, `exec.Command`, etc.
- **Deserialization** (`critical`/`warning`) — `pickle`, `yaml.load` without
  SafeLoader, `marshal`, `jsonpickle`.
- **File operations** (`info`/`warning`) — `open` in write/append mode,
  `shutil`, `fs.writeFile*`, `std::fs::write`, `os.WriteFile`, deletions.
- **Network / data exfiltration** (`info`) — `requests`, `socket`, `fetch`,
  `net.Dial`, `std::net::TcpStream`, and detected network library imports.
- **Weak cryptography** (`warning`) — MD5, SHA1, DES, RC4, `math/rand`.
- **Memory safety** (`info`/`warning`) — Rust `unsafe` blocks, `transmute`,
  raw pointer reads/writes.
- **XSS** (`warning`) — `document.write`, `innerHTML`, `dangerouslySetInnerHTML`.
- **SQL injection** (`warning`) — raw `execute` / `cursor.execute`.
- **Dynamic import / FFI** (`warning`) — `__import__`, `ctypes.CDLL`, etc.

See `config.py` for the full, authoritative rule set per language.

## Risk scoring

Each finding contributes a weight to a 0–100 risk score:

- `critical` → 25
- `warning` → 8
- `info` → 0

The score is capped at 100. The resulting verdict bands are:

- `0` — Clean (no dangerous patterns detected by static analysis)
- `1–20` — Low risk
- `21–50` — Medium risk (deserves review)
- `>50` — High risk (review manually before execution)

Dependency findings are excluded from the score and the CI gate.

## AI analysis

When `--ai-analyze` is enabled, all code findings (with their rich context) are
sent to Gemini in a single request. The model performs **taint analysis** —
tracing whether untrusted/user input can reach a dangerous sink, checking for
sanitization and control-flow guards — and returns one of:

- `CONFIRMED_DANGEROUS` — user-controlled input reaches a sink with no effective sanitization.
- `LIKELY_SAFE` — input is hardcoded/validated, or the sink is not actually dangerous here.
- `NEEDS_REVIEW` — insufficient context; manual review required.

Per-finding AI verdicts, confidence, explanations, and data-flow notes are
embedded in the JSON, Markdown, and HTML reports.

The AI layer uses `google-genai` when available and falls back to the
Gemini REST API via `requests`.

## Output formats

- **text** — human-readable summary for terminals.
- **json** — machine-readable (`report_to_dict`): target, languages, files
  scanned, dependencies, risk score, verdict, disclaimer, summary counts, and
  per-finding details including `ai_analysis`.
- **markdown** — GitHub-friendly report with a risk bar, summary table, and
  per-finding code blocks.
- **html** — self-contained styled report (dark theme) with score circle,
  summary cards, and per-finding code windows and AI analysis blocks.

## Project structure

```
mcp_scan/
├── __init__.py          # Package metadata (__version__)
├── __main__.py          # Entry point for `python -m mcp_scan`
├── models.py            # Data classes (Finding, ScanReport) + risk scoring
├── config.py            # Constants, per-language rules, severity mappings
├── dependency_parser.py # Parse pyproject.toml, package.json, Cargo.toml, go.mod
├── ast_scanner.py       # tree-sitter AST analysis + alias resolution + context
├── ai_analyzer.py       # Gemini AI validation / taint analysis layer
├── renderers.py         # Text, JSON, Markdown, HTML output
└── main.py              # CLI and orchestration
```

## How it works

1. **Resolve target** — clone a Git URL to a temp dir, or use a local path.
2. **Dependency scan** — parse manifests and record declared dependencies.
3. **Source scan** — for each supported source file, parse it with tree-sitter,
   build an alias map, and walk the AST matching dangerous call patterns. For
   each match it records the line, enclosing scope, arguments (with taint
   hints), and relevant imports.
4. **(Optional) AI analysis** — send findings to Gemini for taint-based validation.
5. **Render** — produce the requested report format and apply CI exit-code logic.

## License

See the repository for license details.
