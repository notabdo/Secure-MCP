"""Report renderers: text, JSON, markdown, and HTML.

NOTE: All rendered reports include a disclaimer that static analysis
provides a probabilistic heuristic assessment. For higher confidence,
enable AI analysis as an additional validation layer.
"""

import io
import json
from pathlib import Path

from .config import SEVERITY_LABELS


STATIC_DISCLAIMER = (
    "NOTE: This assessment is based on static heuristics and pattern matching. "
    "It indicates probability of risk, not certainty. "
    "Enable AI analysis for additional validation and manual review when needed."
)


def report_to_dict(report) -> dict:
    """Convert a ScanReport to a dictionary (for JSON output)."""
    real = [f for f in report.findings if f.category != "dependency"]
    return {
        "target": report.target,
        "languages": sorted(report.languages),
        "files_scanned": report.files_scanned,
        "dependencies": report.dependencies,
        "risk_score": report.risk_score(),
        "verdict": report.verdict(),
        "disclaimer": STATIC_DISCLAIMER,
        "summary": {
            "critical": sum(1 for f in real if f.severity == "critical"),
            "warning": sum(1 for f in real if f.severity == "warning"),
            "info": sum(1 for f in real if f.severity == "info"),
        },
        "findings": [
            {
                "severity": f.severity,
                "category": f.category,
                "file": f.file,
                "line": f.line,
                "detail": f.detail,
                "context": f.context,
                "function_context": f.function_context,
                "arguments_context": f.arguments_context,
                "relevant_imports": f.relevant_imports,
                "ai_analysis": f.ai_analysis,
            }
            for f in real
        ],
    }


def _ai_badge_text(f) -> str:
    """Generate AI verdict text for a finding."""
    if not f.ai_analysis:
        return ""
    verdict = f.ai_analysis.get("verdict", "")
    if verdict == "CONFIRMED_DANGEROUS":
        return f" [AI: CONFIRMED_DANGEROUS]"
    elif verdict == "LIKELY_SAFE":
        return f" [AI: LIKELY_SAFE]"
    elif verdict == "NEEDS_REVIEW":
        return f" [AI: NEEDS_REVIEW]"
    return ""


def render_text(report) -> str:
    """Render report as plain text (no emoji)."""
    order = {"critical": 0, "warning": 1, "info": 2}
    buf = io.StringIO()

    buf.write(f"\n{'=' * 60}\n")
    buf.write(f"mcp-scan report: {report.target}\n")
    buf.write(f"{'=' * 60}\n")
    buf.write(
        f"languages: {', '.join(sorted(report.languages)) or 'unknown'}"
        f"   |   files scanned: {report.files_scanned}\n"
    )

    buf.write(f"\n[DEPS] Dependencies ({len(report.dependencies)}):\n")
    for d in report.dependencies[:15]:
        buf.write(f"   - {d}\n")
    if len(report.dependencies) > 15:
        buf.write(f"   ... and {len(report.dependencies) - 15} more\n")

    findings = sorted(
        [f for f in report.findings if f.category != "dependency"],
        key=lambda f: order[f.severity]
    )
    buf.write(f"\n[SCAN] Findings ({len(findings)}):\n")
    for f in findings:
        loc = f":{f.line}" if f.line else ""
        ai_badge = _ai_badge_text(f)
        label = SEVERITY_LABELS.get(f.severity, f"[{f.severity.upper()}]")
        buf.write(
            f"   {label} [{f.category}] {Path(f.file).name}{loc}"
            f" -- {f.detail}{ai_badge}\n"
        )
        if f.context:
            buf.write(f"        | {f.context}\n")
        if f.ai_analysis.get("explanation"):
            conf = f.ai_analysis.get("confidence", "n/a")
            verdict = f.ai_analysis.get("verdict", "")
            buf.write(f"        [AI Verdict: {verdict}] (confidence: {conf})\n")
            buf.write(f"        [AI] {f.ai_analysis['explanation']}\n")
            if f.ai_analysis.get("data_flow"):
                buf.write(f"        [Data Flow] {f.ai_analysis['data_flow']}\n")

    n_crit = sum(1 for f in findings if f.severity == "critical")
    n_warn = sum(1 for f in findings if f.severity == "warning")
    n_info = len(findings) - n_crit - n_warn
    buf.write(f"\n{'-' * 60}\n")
    buf.write(f"Risk score: {report.risk_score()}/100   {report.verdict()}\n")
    buf.write(f"({n_crit} critical, {n_warn} warning, {n_info} info)\n")
    buf.write(f"{STATIC_DISCLAIMER}\n")
    buf.write(f"{'-' * 60}\n")
    return buf.getvalue()


def render_markdown(report) -> str:
    """Render report as Markdown (no emoji)."""
    order = {"critical": 0, "warning": 1, "info": 2}
    findings = sorted(
        [f for f in report.findings if f.category != "dependency"],
        key=lambda f: order[f.severity]
    )
    filled = min(10, report.risk_score() // 10)
    bar = "#" * filled + "-" * (10 - filled)

    lines = [
        "# mcp-scan report",
        "",
        f"**Target:** `{report.target}`  ",
        f"**Languages:** {', '.join(sorted(report.languages)) or 'unknown'}  ",
        f"**Files scanned:** {report.files_scanned}",
        "",
        f"## Risk score: `[{bar}] {report.risk_score()}/100`",
        f"### {report.verdict()}",
        "",
        f"**Disclaimer:** {STATIC_DISCLAIMER}",
        "",
        "| Critical | Warning | Info |",
        "|:---:|:---:|:---:|",
        f"| {sum(1 for f in findings if f.severity == 'critical')} | "
        f"{sum(1 for f in findings if f.severity == 'warning')} | "
        f"{sum(1 for f in findings if f.severity == 'info')} |",
        "",
        "## Findings",
        "",
    ]
    if not findings:
        lines.append("_No dangerous patterns found._")
    for f in findings:
        loc = f":{f.line}" if f.line else ""
        ai_md = ""
        if f.ai_analysis:
            verdict = f.ai_analysis.get("verdict", "NEEDS_REVIEW")
            expl = f.ai_analysis.get("explanation", "")
            conf = f.ai_analysis.get("confidence", "n/a")
            df = f.ai_analysis.get("data_flow", "")
            ai_md = f"\n**AI Verdict:** `{verdict}` (confidence: {conf})\n\n{expl}"
            if df:
                ai_md += f"\n\n**Data Flow:** `{df}`"
        label = SEVERITY_LABELS.get(f.severity, f"[{f.severity.upper()}]")
        lines.append(
            f"### {label} `{f.category}` -- {Path(f.file).name}{loc}{ai_md}"
        )
        lines.append(f"{f.detail}")
        if f.context:
            lines.append(f"```\n{f.context}\n```")
        if f.arguments_context:
            lines.append(f"**Arguments:**\n```\n{f.arguments_context}\n```")
        if f.function_context:
            lines.append(f"**Enclosing Scope:**\n```\n{f.function_context}\n```")
        lines.append("")

    lines.append("## Dependencies")
    lines.append("")
    for d in report.dependencies:
        lines.append(f"- `{d}`")

    return "\n".join(lines)


def render_html(report) -> str:
    """Render report as HTML (no emoji)."""
    order = {"critical": 0, "warning": 1, "info": 2}
    findings = sorted(
        [f for f in report.findings if f.category != "dependency"],
        key=lambda f: order[f.severity]
    )
    score = report.risk_score()
    score_color = "#32b32e" if score <= 20 else ("#b3802e" if score <= 50 else "#b32e2e")
    colors = {"critical": "#b32e2e", "warning": "#b3802e", "info": "#32b32e"}

    rows = []
    for f in findings:
        loc = f":{f.line}" if f.line else ""
        ctx = ""
        if f.context:
            ctx = f"""
            <div class="code-window-report">
              <div class="code-titlebar-report">
                <span class="dot-tl"></span><span class="dot-tl"></span><span class="dot-tl"></span>
                <span class="filename">{Path(f.file).name}{loc}</span>
              </div>
              <pre class="snippet">{f.context}</pre>
            </div>"""

        args_block = ""
        if f.arguments_context:
            args_block = f"""<div class="code-window-report" style="margin-top:8px;"><div class="code-titlebar-report"><span class="filename">Arguments Analysis</span></div><pre class="snippet">{f.arguments_context}</pre></div>"""

        func_block = ""
        if f.function_context:
            func_block = f"""<div class="code-window-report" style="margin-top:8px;"><div class="code-titlebar-report"><span class="filename">Enclosing Function/Class</span></div><pre class="snippet">{f.function_context}</pre></div>"""

        ai_block = ""
        if f.ai_analysis:
            verdict = f.ai_analysis.get("verdict", "NEEDS_REVIEW")
            if verdict == "CONFIRMED_DANGEROUS":
                ai_color = "#b32e2e"
            elif verdict == "LIKELY_SAFE":
                ai_color = "#32b32e"
            else:
                ai_color = "#b3802e"
            conf = f.ai_analysis.get("confidence", "n/a")
            expl = f.ai_analysis.get("explanation", "")
            df = f.ai_analysis.get("data_flow", "")
            df_html = f"<div class=\"ai-dataflow\">Data Flow: {df}</div>" if df else ""
            ai_block = f"""<div class="ai-analysis"><div class="ai-header"><span class="ai-badge" style="background:{ai_color}">AI Verdict: {verdict}</span><span class="ai-confidence">Confidence: {conf}</span></div><div class="ai-explanation">{expl}</div>{df_html}</div>"""

        badge_color = colors.get(f.severity, "#737373")
        label = SEVERITY_LABELS.get(f.severity, f.severity.upper())
        rows.append(f"""
        <div class="finding {f.severity}">
          <div class="finding-head">
            <span class="badge" style="background:{badge_color}">{label} {f.severity}</span>
            <span class="category">{f.category}</span>
            <span class="loc">{Path(f.file).name}{loc}</span>
          </div>
          <div class="detail">{f.detail}</div>
          {ctx}
          {args_block}
          {func_block}
          {ai_block}
        </div>""")

    deps_html = "".join(f"<li><code>{d}</code></li>" for d in report.dependencies)

    return f"""<!DOCTYPE html>
<html lang="en" dir="ltr">
<head>
<meta charset="UTF-8">
<title>mcp-scan report -- {report.target}</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Geist:wght@400;500;600;700&family=Geist+Mono:wght@400;500&display=swap" rel="stylesheet">
<style>
  :root {{
    --accent: #bf7340;
    --accent-bright: #d98a52;
    --accent-string: #d9a577;
    --bg: #0a0a0a;
    --panel: #0d0d0d;
    --panel-2: #141414;
    --border: #1f1f1f;
    --border-2: #262626;
    --border-3: #2a2a2a;
    --text: #ededed;
    --muted: #a3a3a3;
    --dim: #737373;
    --faint: #525252;
    --font-sans: 'Geist', system-ui, sans-serif;
    --font-mono: 'Geist Mono', monospace;
    --color-critical: #b32e2e;
    --color-warning: #b3802e;
    --color-info: #32b32e;
  }}
  * {{ box-sizing: border-box; }}
  body {{
    margin: 0;
    background: var(--bg);
    color: var(--text);
    font-family: var(--font-sans);
    direction: ltr;
    text-align: left;
    padding: 60px 20px;
  }}
  .wrap {{
    max-width: 860px;
    margin: 0 auto;
  }}
  h1 {{
    font-size: 28px;
    font-weight: 700;
    color: #fff;
    margin: 0 0 8px;
    letter-spacing: -0.02em;
    display: flex;
    align-items: center;
    gap: 10px;
  }}
  h1 .logo-dot {{ color: var(--accent); }}
  .meta {{
    color: var(--muted);
    font-size: 14.5px;
    margin-bottom: 32px;
    line-height: 1.6;
  }}
  .meta code {{
    font-family: var(--font-mono);
    background: var(--panel);
    padding: 3px 8px;
    border-radius: 5px;
    border: 1px solid var(--border-2);
    color: var(--text);
    direction: ltr;
    display: inline-block;
  }}
  .disclaimer {{
    background: var(--panel);
    border: 1px solid var(--border-2);
    border-radius: 10px;
    padding: 16px 20px;
    margin-bottom: 28px;
    color: var(--muted);
    font-size: 14px;
    line-height: 1.6;
  }}
  .disclaimer strong {{ color: var(--text); }}
  .score-box {{
    display: flex;
    align-items: center;
    gap: 24px;
    background: var(--panel);
    border: 1px solid var(--border-2);
    border-radius: 12px;
    padding: 24px;
    margin-bottom: 28px;
  }}
  .score-circle {{
    width: 90px;
    height: 90px;
    border-radius: 50%;
    border: 6px solid {score_color};
    display: flex;
    align-items: center;
    justify-content: center;
    font-size: 26px;
    font-weight: 700;
    color: #fff;
    flex-shrink: 0;
    font-family: var(--font-sans);
    background: var(--panel-2);
  }}
  .verdict {{
    font-size: 17px;
    line-height: 1.5;
  }}
  .verdict-title {{
    font-size: 19px;
    font-weight: 700;
    color: #fff;
    margin-bottom: 4px;
  }}
  .verdict-sub {{
    color: var(--muted);
    font-size: 13.5px;
  }}
  .summary {{
    display: flex;
    gap: 16px;
    margin-bottom: 32px;
  }}
  .summary div {{
    flex: 1;
    background: var(--panel);
    border: 1px solid var(--border-2);
    border-radius: 10px;
    padding: 16px;
    text-align: center;
    font-weight: 500;
    color: var(--muted);
  }}
  .summary .num {{
    font-size: 28px;
    font-weight: 700;
    margin-bottom: 4px;
    font-family: var(--font-sans);
  }}
  h2 {{
    font-size: 18px;
    font-weight: 700;
    color: #fff;
    border-bottom: 1px solid var(--border);
    padding-bottom: 10px;
    margin-top: 40px;
    margin-bottom: 20px;
  }}
  .finding {{
    background: var(--panel);
    border: 1px solid var(--border-3);
    border-radius: 10px;
    padding: 20px;
    margin-bottom: 16px;
    display: flex;
    flex-direction: column;
    gap: 12px;
  }}
  .finding-head {{
    display: flex;
    gap: 12px;
    align-items: center;
    font-size: 13.5px;
    flex-wrap: wrap;
  }}
  .badge {{
    color: #fff;
    padding: 3px 10px;
    border-radius: 6px;
    font-size: 12px;
    font-weight: 600;
  }}
  .category {{
    color: var(--muted);
    font-family: var(--font-mono);
    font-size: 13px;
    background: var(--panel-2);
    padding: 2px 8px;
    border: 1px solid var(--border-3);
    border-radius: 5px;
    direction: ltr;
  }}
  .loc {{
    margin-left: auto;
    font-family: var(--font-mono);
    color: var(--accent-bright);
    font-size: 13px;
    direction: ltr;
  }}
  .detail {{
    font-size: 15px;
    font-weight: 500;
    color: var(--text);
    line-height: 1.5;
  }}
  .code-window-report {{
    background: var(--panel-2);
    border: 1px solid var(--border-3);
    border-radius: 8px;
    overflow: hidden;
    margin-top: 4px;
    direction: ltr;
  }}
  .code-titlebar-report {{
    display: flex;
    align-items: center;
    gap: 6px;
    padding: 8px 12px;
    border-bottom: 1px solid var(--border);
    justify-content: flex-start;
  }}
  .code-titlebar-report .dot-tl {{
    width: 8px;
    height: 8px;
    border-radius: 50%;
    background: var(--border-3);
  }}
  .code-titlebar-report .filename {{
    margin-left: 6px;
    font: 400 11px var(--font-mono);
    color: var(--dim);
  }}
  pre.snippet {{
    margin: 0;
    padding: 16px;
    font: 400 13px/1.7 var(--font-mono);
    color: #e5e5e5;
    overflow-x: auto;
    text-align: left;
    background: transparent;
    border: none;
    border-radius: 0;
  }}
  .ai-analysis {{
    margin-top: 4px;
    padding: 16px;
    background: var(--panel-2);
    border: 1px solid var(--border-3);
    border-radius: 8px;
    display: flex;
    flex-direction: column;
    gap: 10px;
  }}
  .ai-header {{
    display: flex;
    align-items: center;
    gap: 12px;
    flex-wrap: wrap;
  }}
  .ai-badge {{
    color: #fff;
    padding: 3px 10px;
    border-radius: 6px;
    font-size: 12px;
    font-weight: 700;
  }}
  .ai-confidence {{
    color: var(--muted);
    font-size: 12.5px;
  }}
  .ai-explanation {{
    color: var(--text);
    font-size: 14.5px;
    line-height: 1.6;
  }}
  .ai-dataflow {{
    color: var(--accent-string);
    font-family: var(--font-mono);
    font-size: 13px;
    padding: 8px;
    background: var(--panel);
    border-radius: 5px;
    border: 1px solid var(--border-2);
  }}
  ul.deps {{
    columns: 2;
    font-size: 13.5px;
    color: var(--muted);
    padding-left: 20px;
    margin: 0;
  }}
  ul.deps li {{ margin-bottom: 8px; }}
  ul.deps code {{
    font-family: var(--font-mono);
    background: var(--panel);
    border: 1px solid var(--border-2);
    padding: 2px 6px;
    border-radius: 4px;
    color: var(--text);
    direction: ltr;
    display: inline-block;
  }}
  @media (max-width: 768px) {{
    .summary {{ flex-direction: column; gap: 12px; }}
    ul.deps {{ columns: 1; }}
    .score-box {{ flex-direction: column; text-align: center; }}
    .score-circle {{ margin: 0 auto; }}
  }}
</style>
</head>
<body>
<div class="wrap">
  <h1>Scan Report <span dir="ltr">mcp-scan</span><span class="logo-dot">.</span></h1>
  <div class="meta">Target: <code>{report.target}</code> &middot; Languages: {', '.join(sorted(report.languages)) or 'unknown'} &middot; Files scanned: {report.files_scanned}</div>

  <div class="disclaimer">
    <strong>Disclaimer:</strong> {STATIC_DISCLAIMER}
  </div>

  <div class="score-box">
    <div class="score-circle">{score}</div>
    <div class="verdict">
      <div class="verdict-title">{report.verdict()}</div>
      <div class="verdict-sub">Overall risk score out of 100</div>
    </div>
  </div>

  <div class="summary">
    <div><div class="num" style="color:var(--color-critical)">{sum(1 for f in findings if f.severity == 'critical')}</div>Critical</div>
    <div><div class="num" style="color:var(--color-warning)">{sum(1 for f in findings if f.severity == 'warning')}</div>Warning</div>
    <div><div class="num" style="color:var(--color-info)">{sum(1 for f in findings if f.severity == 'info')}</div>Info</div>
  </div>

  <h2>Detected issues and vulnerabilities ({len(findings)})</h2>
  {"".join(rows) if rows else "<p style='color:var(--muted)'>No dangerous patterns found.</p>"}

  <h2>Dependencies and libraries ({len(report.dependencies)})</h2>
  <ul class="deps">{deps_html}</ul>
</div>
</body>
</html>"""
