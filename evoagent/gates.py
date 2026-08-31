"""Deterministic finding and release gates shared by all run modes."""
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Tuple

from .diff_parser import ParsedDiff
from .models import Finding, Severity


@dataclass
class GateResult:
    accepted: List[Finding]
    rejected: List[Dict[str, Any]]
    checks: Dict[str, Any]


class FindingGate:
    STRONG_EVIDENCE_TOOLS = {
        "ast_analyze", "symbol", "git_context", "run_scanners",
        "semgrep", "bandit", "eslint", "typecheck", "test", "diff-ast-analyze",
    }

    def __init__(self, minimum_confidence: float = 0.55):
        self.minimum_confidence = minimum_confidence

    def apply(self, findings: Iterable[Finding], parsed: ParsedDiff) -> GateResult:
        valid_locations = {(item.path, item.line): item.content for item in parsed.added_lines}
        accepted, rejected = [], []
        counters = {"format": 0, "evidence": 0, "confidence": 0, "release": 0}
        for finding in findings:
            reasons = []
            location = (finding.path, finding.line)
            if (
                location not in valid_locations or not finding.rule_id.strip()
                or not finding.title.strip() or not finding.explanation.strip()
            ):
                reasons.append("format gate: invalid location or required field")
                counters["format"] += 1

            quoted = finding.evidence.strip()
            line = valid_locations.get(location, "").strip()
            exact_line = bool(quoted and quoted in line)
            refs = [item for item in finding.evidence_refs if isinstance(item, dict)]
            valid_refs = [item for item in refs if item.get("evidence_id") and item.get("tool")]
            strong_refs = [
                item for item in valid_refs
                if str(item.get("tool")) in self.STRONG_EVIDENCE_TOOLS
            ]
            if not exact_line and not valid_refs and not finding.call_chain:
                reasons.append("evidence gate: no matching code, call chain or tool evidence")
                counters["evidence"] += 1
            if finding.severity in {Severity.CRITICAL, Severity.HIGH} and not (
                strong_refs or finding.call_chain
            ):
                reasons.append(
                    "evidence gate: high-risk finding requires AST/scanner/call-chain evidence"
                )
                counters["evidence"] += 1
            if finding.confidence < self.minimum_confidence:
                reasons.append("confidence gate: score below %.2f" % self.minimum_confidence)
                counters["confidence"] += 1
            if finding.severity in {Severity.CRITICAL, Severity.HIGH} and (
                not finding.fix.strip() or not finding.test.strip()
            ):
                reasons.append("release gate: high-risk finding lacks fix or test guidance")
                counters["release"] += 1

            finding.gate = {
                "passed": not reasons, "reasons": reasons,
                "exact_location_evidence": exact_line,
                "strong_evidence_count": len(strong_refs),
            }
            if reasons:
                rejected.append({
                    "rule_id": finding.rule_id, "path": finding.path,
                    "line": finding.line, "reasons": reasons,
                })
            else:
                accepted.append(finding)
        return GateResult(
            accepted, rejected,
            {
                "format": {"rejected": counters["format"]},
                "evidence": {"rejected": counters["evidence"]},
                "confidence": {
                    "minimum": self.minimum_confidence,
                    "rejected": counters["confidence"],
                },
                "release": {"rejected": counters["release"]},
                "accepted": len(accepted), "rejected": len(rejected),
            },
        )
