"""CLI entry point for mcp-scan.

Usage:
    python -m mcp_scan <target> [options]

The static analyzer provides a probabilistic risk assessment based on
AST pattern matching. For higher-confidence validation, enable AI
analysis with --ai-analyze.
"""

import argparse
import json
import subprocess
import sys
import tempfile
import warnings
from pathlib import Path

warnings.filterwarnings("ignore", category=FutureWarning, module="tree_sitter")

from .models import ScanReport
from .dependency_parser import scan_dependencies
from .ast_scanner import scan_source_file
from .ai_analyzer import analyze_with_gemini
from .renderers import render_text, render_html, render_markdown, report_to_dict
from .config import EXT_TO_LANG, SKIP_DIRS


def resolve_target(target: str) -> Path:
    """Resolve a target path or Git URL to a local directory."""
    if target.startswith("http://") or target.startswith("https://"):
        tmp = Path(tempfile.mkdtemp(prefix="mcp-scan-"))
        print(f"[DOWNLOAD] Cloning {target} -> {tmp}", file=sys.stderr)
        subprocess.run(
            ["git", "clone", "--depth", "1", target, str(tmp)],
            check=True
        )
        return tmp
    return Path(target)


def scan_target(target_dir: str) -> ScanReport:
    """Run the full scan pipeline on a target directory."""
    root = resolve_target(target_dir)
    report = ScanReport(target=str(root))
    scan_dependencies(root, report)

    for f in root.rglob("*"):
        if not f.is_file() or any(part in SKIP_DIRS for part in f.parts):
            continue
        if "test" in f.stem.lower():
            continue
        if f.suffix in EXT_TO_LANG:
            
            scan_source_file(f, EXT_TO_LANG[f.suffix], report)

    return report


def build_arg_parser():
    """Build the argument parser."""
    p = argparse.ArgumentParser(
        prog="mcp-scan",
        description=(
            "Security scanner for MCP servers -- dependencies + static analysis + optional AI review. "
            "Static analysis provides a heuristic/probabilistic assessment. "
            "Enable --ai-analyze for additional AI-powered validation."
        )
    )
    p.add_argument(
        "target",
        help="Local path or GitHub link to the MCP server"
    )
    p.add_argument(
        "-f", "--format",
        choices=["text", "json", "markdown", "html"],
        default="text",
        help="Report format (default: text)"
    )
    p.add_argument(
        "-o", "--output",
        help="Write report to a file instead of stdout"
    )
    p.add_argument(
        "--fail-on",
        choices=["critical", "warning", "none"],
        default="critical",
        help=(
            "Exit code = 1 if there are findings of this severity or higher. "
            "Useful as a CI gate (default: critical)"
        )
    )
    p.add_argument(
        "--min-score",
        type=int,
        default=None,
        help="Exit code = 1 if risk score >= this number"
    )
    # AI Analysis args
    p.add_argument(
        "--ai-analyze",
        action="store_true",
        help=(
            "Enable Gemini AI analysis for findings (sends all snippets in a one-shot request). "
            "Strongly recommended to reduce false positives from static analysis."
        )
    )
    p.add_argument(
        "--gemini-api-key",
        default=None,
        help="Gemini API key -- required if --ai-analyze is enabled"
    )
    p.add_argument(
        "--gemini-model",
        default="gemini-3.1-flash-lite",
        help="Gemini model identifier (default: gemini-3.1-flash-lite)"
    )
    return p


def main():
    """Main entry point."""
    args = build_arg_parser().parse_args()

    try:
        report = scan_target(args.target)
    except subprocess.CalledProcessError:
        print(f"[ERROR] Failed to clone/access: {args.target}", file=sys.stderr)
        sys.exit(2)
    except FileNotFoundError:
        print(f"[ERROR] Path does not exist: {args.target}", file=sys.stderr)
        sys.exit(2)

    # --- AI Analysis ---
    if args.ai_analyze:
        if not args.gemini_api_key:
            print("[ERROR] --ai-analyze requires --gemini-api-key", file=sys.stderr)
            sys.exit(2)
        analyze_with_gemini(report, args.gemini_api_key, args.gemini_model)

    renderers = {
        "text": render_text,
        "json": lambda r: json.dumps(report_to_dict(r), ensure_ascii=False, indent=2),
        "markdown": render_markdown,
        "html": render_html,
    }
    output = renderers[args.format](report)

    if args.output:
        Path(args.output).write_text(output, encoding="utf-8")
        print(f"[OK] Report written to: {args.output}", file=sys.stderr)
    else:
        print(output)

    # --- exit code logic, designed to be used as a CI gate ---
    exit_code = 0
    real_findings = [f for f in report.findings if f.category != "dependency"]
    if args.fail_on == "critical" and any(f.severity == "critical" for f in real_findings):
        exit_code = 1
    elif args.fail_on == "warning" and any(f.severity in ("critical", "warning") for f in real_findings):
        exit_code = 1
    if args.min_score is not None and report.risk_score() >= args.min_score:
        exit_code = 1

    sys.exit(exit_code)


if __name__ == "__main__":
    main()
