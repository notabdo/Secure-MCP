"""Gemini AI analysis with deep taint analysis and data flow reasoning."""

import json
import re
import sys
from pathlib import Path

from .models import ScanReport


def _build_ai_prompt(findings: list) -> str:
    """Build a comprehensive prompt for deep security analysis.

    Each finding includes:
    - The exact line of code
    - The full enclosing function/class
    - Arguments passed to the dangerous call (with type analysis)
    - Relevant imports

    The AI is asked to perform taint analysis: trace where data comes from,
    whether user input can reach the sink, and whether sanitization exists.
    """
    lines = [
        "You are an expert security code reviewer performing DEEP TAINT ANALYSIS.",
        "Your goal is to determine whether each finding is ACTUALLY exploitable.",
        "",
        "For EACH finding, analyze the following:",
        "",
        "1. DATA FLOW (Taint Analysis):",
        "   - Where do the arguments come from? Are they hardcoded strings, user input,",
        "     environment variables, file reads, network responses, or computed values?",
        "   - Trace the data path: can UNSANITIZED user input reach the dangerous sink?",
        "",
        "2. SANITIZATION / VALIDATION:",
        "   - Is there input validation, escaping, whitelisting, or type checking?",
        "   - Are there try/except or error handlers that prevent exploitation?",
        "",
        "3. CONTROL FLOW:",
        "   - Is the dangerous call inside a conditional block that restricts execution?",
        "   - Is it in a test file, internal utility, or publicly exposed API endpoint?",
        "",
        "4. ARGUMENT ANALYSIS:",
        "   - [STATIC_STRING]: Hardcoded values are usually SAFE.",
        "   - [VARIABLE]: Trace the variable back to its source.",
        "   - [CONCATENATION] / [FORMATTED_STRING] / [TEMPLATE_LITERAL]: HIGH RISK if user input is concatenated.",
        "   - [CALL_RESULT]: Analyze what the called function returns.",
        "",
        "CLASSIFICATION RULES:",
        "- CONFIRMED_DANGEROUS: User-controlled input reaches a dangerous sink with NO effective sanitization.",
        "- LIKELY_SAFE: Input is hardcoded, strongly validated, or the sink is not actually dangerous in this context.",
        "- NEEDS_REVIEW: Insufficient context to determine; requires manual human review.",
        "",
        "Return ONLY a valid JSON array. No markdown, no explanations outside JSON.",
        'Format:',
        '[{"index":0,"verdict":"CONFIRMED_DANGEROUS","explanation":"User input from req.query.id is passed directly to eval() without validation","confidence":"high","data_flow":"req.query.id -> variable x -> eval(x)"}, ...]',
        "",
        "Fields:",
        '- verdict: "CONFIRMED_DANGEROUS" | "LIKELY_SAFE" | "NEEDS_REVIEW"',
        '- explanation: 1-3 sentences of reasoning',
        '- confidence: "high" | "medium" | "low"',
        '- data_flow: Brief description of the data path (source -> ... -> sink)',
        "",
        "=== FINDINGS ===",
    ]
    for i, f in enumerate(findings):
        lines.append(f"\n--- Finding {i} ---")
        lines.append(f"File: {Path(f.file).name}:{f.line}")
        lines.append(f"Category: {f.category}")
        lines.append(f"Scanner Severity: {f.severity}")
        lines.append(f"Scanner Detail: {f.detail}")
        if f.relevant_imports:
            lines.append(f"Relevant Imports:")
            for imp in f.relevant_imports:
                lines.append(f"  {imp}")
        lines.append(f"\nContext Line:\n{f.context}")
        if f.arguments_context:
            lines.append(f"\n{f.arguments_context}")
        if f.function_context:
            lines.append(f"\n{f.function_context}")
    return "\n".join(lines)


def analyze_with_gemini(report: ScanReport, api_key: str, model: str = "gemini-3.1-flash-lite"):
    """Send all findings to Gemini with rich context for deep analysis.
Gemini 3.1 Flash Lite
    NOTE: Static analysis produces probabilistic heuristics. This AI layer
    performs taint analysis by examining data flow, sanitization, and control
    flow to reduce false positives and confirm actual exploitability.
    """
    real_findings = [
        f for f in report.findings
        if f.category != "dependency" and f.context
    ]
    if not real_findings:
        print("[INFO] No code findings to analyze with AI.", file=sys.stderr)
        return

    prompt = _build_ai_prompt(real_findings)
    response_text = None

    # Try google.genai (new official SDK) first
    try:
        from google import genai
        client = genai.Client(api_key=api_key)
        resp = client.models.generate_content(
            model=model,
            contents=prompt,
            config={"response_mime_type": "application/json"}
        )
        response_text = resp.text
        print("[OK] AI deep analysis completed via google.genai", file=sys.stderr)
    except ImportError:
        pass
    except Exception as e:
        print(f"[WARN] google.genai error: {e}", file=sys.stderr)

    # Fallback to REST API
    if response_text is None:
        try:
            import requests
            url = (
                f"https://generativelanguage.googleapis.com/v1beta/models/"
                f"{model}:generateContent?key={api_key}"
            )
            payload = {
                "contents": [{"parts": [{"text": prompt}]}],
                "generationConfig": {"responseMimeType": "application/json"}
            }
            r = requests.post(url, json=payload, timeout=120)
            r.raise_for_status()
            data = r.json()
            response_text = data["candidates"][0]["content"]["parts"][0]["text"]
            print("[OK] AI deep analysis completed via REST API", file=sys.stderr)
        except Exception as e:
            print(f"[WARN] Gemini REST API error: {e}", file=sys.stderr)
            return

    # Parse JSON response
    analyses = []
    try:
        analyses = json.loads(response_text)
    except json.JSONDecodeError:
        m = re.search(r'\[.*\]', response_text, re.DOTALL)
        if m:
            try:
                analyses = json.loads(m.group())
            except json.JSONDecodeError:
                pass

    if not isinstance(analyses, list):
        print("[WARN] Gemini returned unexpected format, skipping AI analysis.", file=sys.stderr)
        return

    applied = 0
    for a in analyses:
        idx = a.get("index", 0)
        if 0 <= idx < len(real_findings):
            real_findings[idx].ai_analysis = {
                "verdict": a.get("verdict", "NEEDS_REVIEW"),
                "is_dangerous": a.get("verdict") == "CONFIRMED_DANGEROUS",
                "explanation": a.get("explanation", ""),
                "confidence": a.get("confidence", "low"),
                "data_flow": a.get("data_flow", ""),
            }
            applied += 1

    print(f"[OK] AI deep analysis applied to {applied}/{len(real_findings)} findings.", file=sys.stderr)
