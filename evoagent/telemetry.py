"""Per-review accounting for real model/tool calls and complete agent traces."""
from dataclasses import asdict, dataclass, field
import threading
import time
from typing import Any, Dict, List, Optional


@dataclass
class ModelCall:
    role: str
    provider: str
    model: str
    input_tokens: int
    output_tokens: int
    cost_usd: float
    duration_ms: int
    ok: bool
    error: str = ""


@dataclass
class ToolCall:
    role: str
    tool: str
    arguments: Dict[str, Any]
    ok: bool
    duration_ms: int
    result_preview: str = ""
    error: str = ""


class ExecutionLedger:
    def __init__(
        self, mode: str, input_cost_per_million: float = 0.0,
        output_cost_per_million: float = 0.0,
    ):
        self.mode = mode
        self.input_cost_per_million = max(0.0, input_cost_per_million)
        self.output_cost_per_million = max(0.0, output_cost_per_million)
        self.started = time.monotonic()
        self.model_calls: List[ModelCall] = []
        self.tool_calls: List[ToolCall] = []
        self.agent_traces: Dict[str, List[Dict[str, Any]]] = {}
        self._lock = threading.Lock()

    def estimate_cost(self, input_tokens: int, output_tokens: int) -> float:
        return round(
            input_tokens * self.input_cost_per_million / 1_000_000
            + output_tokens * self.output_cost_per_million / 1_000_000,
            8,
        )

    def record_model(
        self, role: str, provider: str, model: str, usage: Dict[str, Any],
        duration_ms: int, ok: bool = True, error: str = "",
    ) -> None:
        input_tokens = int(usage.get("prompt_tokens", usage.get("input_tokens", 0)) or 0)
        output_tokens = int(usage.get("completion_tokens", usage.get("output_tokens", 0)) or 0)
        reported_cost = usage.get("cost")
        cost = (
            float(reported_cost) if reported_cost is not None
            else self.estimate_cost(input_tokens, output_tokens)
        )
        call = ModelCall(
            role, provider, model, input_tokens, output_tokens, round(cost, 8),
            int(duration_ms), bool(ok), str(error)[:1000],
        )
        with self._lock:
            self.model_calls.append(call)

    def record_tool(
        self, role: str, tool: str, arguments: Dict[str, Any], ok: bool,
        duration_ms: int, result: Any = "", error: str = "",
    ) -> None:
        preview = str(result)[:1000]
        call = ToolCall(
            role, tool, dict(arguments), bool(ok), int(duration_ms), preview,
            str(error)[:1000],
        )
        with self._lock:
            self.tool_calls.append(call)

    def trace(self, role: str, event: str, **detail) -> None:
        item = {
            "sequence": 0, "event": event,
            "elapsed_ms": int((time.monotonic() - self.started) * 1000), **detail,
        }
        with self._lock:
            values = self.agent_traces.setdefault(role, [])
            item["sequence"] = len(values) + 1
            values.append(item)

    def summary(self, include_trace: bool = True) -> Dict[str, Any]:
        with self._lock:
            models = [asdict(item) for item in self.model_calls]
            tools = [asdict(item) for item in self.tool_calls]
            traces = {key: list(value) for key, value in self.agent_traces.items()}
        return {
            "mode": self.mode,
            "llm_calls": len(models),
            "tool_calls": len(tools),
            "input_tokens": sum(item["input_tokens"] for item in models),
            "output_tokens": sum(item["output_tokens"] for item in models),
            "total_tokens": sum(
                item["input_tokens"] + item["output_tokens"] for item in models
            ),
            "cost_usd": round(sum(item["cost_usd"] for item in models), 8),
            "duration_ms": int((time.monotonic() - self.started) * 1000),
            "failed_model_calls": sum(not item["ok"] for item in models),
            "failed_tool_calls": sum(not item["ok"] for item in tools),
            "model_call_log": models,
            "tool_call_log": tools,
            "agent_traces": traces if include_trace else {},
        }
