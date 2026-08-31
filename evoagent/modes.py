"""Truthful execution modes and product component taxonomy."""
from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, Iterable, Optional

from .models import ComponentKind


class RunMode(str, Enum):
    RULES_ONLY = "rules-only"
    HYBRID = "hybrid"
    AGENTIC = "agentic"

    @classmethod
    def parse(cls, value: Optional[str], default: "RunMode" = None) -> "RunMode":
        fallback = default or cls.RULES_ONLY
        if value is None or not str(value).strip():
            return fallback
        try:
            return cls(str(value).strip().lower())
        except ValueError as exc:
            raise ValueError("mode must be rules-only, hybrid or agentic") from exc


@dataclass(frozen=True)
class ModeResolution:
    requested: RunMode
    effective: RunMode
    model_configured: bool
    fallback_reason: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "requested": self.requested.value,
            "effective": self.effective.value,
            "model_configured": self.model_configured,
            "fallback_reason": self.fallback_reason,
        }


def resolve_mode(requested: Optional[str], model_configured: bool) -> ModeResolution:
    # The safe default is deliberately derived from actual capabilities.
    default = RunMode.HYBRID if model_configured else RunMode.RULES_ONLY
    selected = RunMode.parse(requested, default)
    if selected is not RunMode.RULES_ONLY and not model_configured:
        return ModeResolution(
            selected, RunMode.RULES_ONLY, False,
            "No model is configured; the request ran as rules-only.",
        )
    return ModeResolution(selected, selected, model_configured)


def component(kind: ComponentKind, name: str, enabled: bool = True, **detail) -> dict:
    return {"kind": kind.value, "name": name, "enabled": bool(enabled), **detail}


def public_taxonomy() -> Dict[str, Any]:
    return {
        "component_kinds": {
            ComponentKind.LLM_AGENT.value: (
                "Reasons from a goal, autonomously selects tools or stops, and may revise."
            ),
            ComponentKind.TOOL_SCANNER.value: (
                "Produces facts through rules, AST, Semgrep, code search or command execution."
            ),
            ComponentKind.GATE.value: (
                "Validates format, evidence, confidence and release eligibility."
            ),
        },
        "run_modes": {
            RunMode.RULES_ONLY.value: "Deterministic scanners and gates; no model calls.",
            RunMode.HYBRID.value: "Deterministic scanners plus one LLM agent and gates.",
            RunMode.AGENTIC.value: "Planner, two specialists and a blind critic are LLM agents.",
        },
    }
