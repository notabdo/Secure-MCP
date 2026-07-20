"""Data models for scan findings and reports."""

from dataclasses import dataclass, field


@dataclass
class Finding:
    """Represents a single security finding with rich context for AI analysis."""
    severity: str        # critical | warning | info
    category: str
    file: str
    line: int
    detail: str
    context: str = ""              # The specific line of code
    function_context: str = ""     # Full enclosing function/method body
    relevant_imports: list = field(default_factory=list)  # Related imports
    arguments_context: str = ""    # Arguments passed to the dangerous call
    ai_analysis: dict = field(default_factory=dict)
    # ai_analysis: {"verdict": str, "explanation": str, "confidence": str, "data_flow": str}


@dataclass
class ScanReport:
    """Aggregates all findings for a scanned target."""
    target: str
    dependencies: list[str] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    languages: set[str] = field(default_factory=set)
    files_scanned: int = 0

    def add(self, severity, category, file, line, detail, context="",
            function_context="", relevant_imports=None, arguments_context=""):
        """Add a new finding to the report."""
        self.findings.append(Finding(
            severity=severity,
            category=category,
            file=file,
            line=line,
            detail=detail,
            context=context,
            function_context=function_context,
            relevant_imports=relevant_imports or [],
            arguments_context=arguments_context,
        ))

    def risk_score(self) -> int:
        """Calculate a numeric risk score (0-100).

        NOTE: This is a heuristic based on static pattern matching.
        It indicates *probability* of issues, not certainty.
        For a definitive assessment, enable AI analysis.
        """
        weights = {"critical": 25, "warning": 8, "info": 0}
        real = [f for f in self.findings if f.category != "dependency"]
        score = sum(weights[f.severity] for f in real)
        return min(score, 100)

    def verdict(self) -> str:
        """Return a human-readable risk verdict.

        NOTE: This verdict is derived from static heuristics and pattern
        matching. It represents a *probabilistic* assessment, not a
        guarantee. Always review findings manually or enable AI analysis
        for additional validation.
        """
        s = self.risk_score()
        if s == 0:
            return "Clean -- no dangerous patterns detected by static analysis"
        if s <= 20:
            return "Low risk (static heuristic)"
        if s <= 50:
            return "Medium risk -- deserves review before use (static heuristic)"
        return "High risk -- review the code manually before any execution (static heuristic)"
