"""Tenant-aware working, episodic and semantic memory for review agents.

**这个模块刻意没有接进 agentic_core（评测链路）。** 记一下为什么，
否则下一个人看到"写了分层记忆但评测里没用"会当成漏接的活儿去补。

三条路都想过：

1. 接进 agentic_core，让 specialist 能召回历史审查结论。
2. 留在 service.py（产品链路）不动，README 里标明它不在评测链路上。← 选这条
3. 挪到 prototypes/。

选 2、不选 1 的理由不是工作量，是**接进去会毁掉评测本身**。基准集的
holdout 之所以能说明问题，前提是每个 case 相互独立；一旦跨 case 记忆，
审第 N 个 case 时会召回第 N-1 个的结论，独立性就没了：
- 同类缺陷在基准集里重复出现，第二次的"发现"可能是召回而不是检出，
  指标会虚高，而且是**朝着我们希望的方向**虚高（最难发现的偏差）；
- Validation 上调过的提示词，其收益会通过记忆漏到 Holdout，
  那条"Holdout 提升远小于 Validation"的检验就失效了——而这条检验
  正是整个评测里唯一能挡住过拟合的东西。

要接的话得先有隔离手段（按 case 分租户 + 每个 case 跑完清空），
那是另一件事，成本比"接上去"高得多，收益也要单独量。在有那套隔离之前，
不接是正确答案，不是欠的债。

不选 3 是因为 prototypes/ 的判据是"没被量过**且当前没在用**"；
这个模块是 service.py 在跑的活代码，有单测，只是不在评测口径内。
"""
from datetime import datetime, timedelta, timezone
import hashlib
import json
import re
from typing import Any, Dict, Iterable, List, Optional, Sequence

from .store import utc_now


TOKEN = re.compile(r"[A-Za-z0-9_./:-]{2,}")
VALID_SCOPES = {"working", "episodic", "semantic", "procedural"}


def _tokens(value: str) -> set:
    return {item.lower() for item in TOKEN.findall(value)}


class MemoryManager:
    """Persist and retrieve bounded memories without hiding store side effects."""

    def __init__(
        self, store, enabled: bool = True, recall_limit: int = 6,
        working_ttl_seconds: int = 86400,
    ):
        self.store = store
        self.enabled = enabled
        self.recall_limit = max(1, recall_limit)
        self.working_ttl_seconds = max(60, working_ttl_seconds)

    def remember(
        self, tenant_id: str, repository: str, scope: str, kind: str,
        content: str, metadata: Optional[Dict[str, Any]] = None,
        task_id: str = "", agent: str = "", importance: float = 0.5,
        ttl_seconds: Optional[int] = None,
    ) -> Optional[Dict[str, Any]]:
        if not self.enabled or not content.strip():
            return None
        if scope not in VALID_SCOPES:
            raise ValueError("unsupported memory scope: %s" % scope)
        importance = max(0.0, min(1.0, float(importance)))
        metadata = dict(metadata or {})
        normalized = content.strip()[:8000]
        fingerprint = json.dumps({
            "tenant": tenant_id, "repository": repository, "scope": scope,
            "kind": kind, "content": normalized, "metadata": metadata,
        }, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        memory_id = hashlib.sha256(fingerprint.encode("utf-8")).hexdigest()
        ttl = self.working_ttl_seconds if scope == "working" and ttl_seconds is None else ttl_seconds
        expires_at = None
        if ttl:
            expires_at = (
                datetime.now(timezone.utc) + timedelta(seconds=max(1, int(ttl)))
            ).isoformat()
        record = {
            "id": memory_id, "tenant_id": tenant_id or "default",
            "repository": repository, "task_id": task_id, "agent": agent,
            "scope": scope, "kind": kind, "content": normalized,
            "keywords": sorted(_tokens(normalized) | _tokens(kind)),
            "metadata": metadata, "importance": importance,
            "created_at": utc_now(), "expires_at": expires_at,
        }
        return self.store.save_agent_memory(record)

    def recall(
        self, tenant_id: str, repository: str, query: str,
        scopes: Sequence[str] = ("semantic", "episodic"),
        limit: Optional[int] = None,
    ) -> List[Dict[str, Any]]:
        if not self.enabled:
            return []
        purge = getattr(self.store, "purge_expired_agent_memories", None)
        if purge:
            purge()
        selected_scopes = tuple(scope for scope in scopes if scope in VALID_SCOPES)
        if not selected_scopes:
            return []
        candidates = self.store.list_agent_memories(
            tenant_id or "default", repository, selected_scopes, 200
        )
        query_tokens = _tokens(query)
        ranked = []
        for index, item in enumerate(candidates):
            memory_tokens = set(item.get("keywords") or []) | _tokens(item.get("content", ""))
            overlap = len(query_tokens.intersection(memory_tokens))
            coverage = overlap / max(1, len(query_tokens))
            specificity = overlap / max(1, len(memory_tokens))
            score = (
                coverage * 0.55 + specificity * 0.15
                + float(item.get("importance", 0.5)) * 0.25
                + (0.05 / (index + 1))
            )
            if query_tokens and overlap == 0 and item.get("scope") != "semantic":
                continue
            value = dict(item)
            value["recall_score"] = round(score, 4)
            ranked.append(value)
        size = max(1, limit or self.recall_limit)
        return sorted(
            ranked,
            key=lambda item: (-item["recall_score"], item.get("created_at", "")),
        )[:size]

    def remember_finding(
        self, tenant_id: str, repository: str, task_id: str,
        finding: Dict[str, Any], approved: bool, reasons: Iterable[str] = (),
    ) -> Optional[Dict[str, Any]]:
        decision = "approved" if approved else "rejected"
        content = (
            "%s finding %s at %s:%s. Evidence: %s. Explanation: %s. "
            "Fix: %s. Decision reasons: %s"
        ) % (
            decision, finding.get("rule_id", "unknown"), finding.get("path", ""),
            finding.get("line", 0), finding.get("evidence", ""),
            finding.get("explanation", ""), finding.get("fix", ""),
            "; ".join(str(item) for item in reasons),
        )
        return self.remember(
            tenant_id, repository, "episodic", "finding_%s" % decision,
            content, {"finding": finding, "approved": approved}, task_id=task_id,
            importance=0.8 if approved else 0.45,
        )

    def remember_feedback(
        self, tenant_id: str, repository: str, task_id: str, category: str,
        finding: Optional[Dict[str, Any]], note: str,
    ) -> Optional[Dict[str, Any]]:
        finding = dict(finding or {})
        content = "Feedback %s for %s at %s:%s. Note: %s" % (
            category, finding.get("rule_id", "task"), finding.get("path", ""),
            finding.get("line", 0), note,
        )
        return self.remember(
            tenant_id, repository, "semantic", "review_feedback", content,
            {"category": category, "finding": finding}, task_id=task_id,
            importance=0.95 if category in {"false_positive", "missed_issue", "bad_fix"} else 0.7,
        )

    def forget_working(self, task_id: str) -> int:
        if not self.enabled:
            return 0
        return self.store.delete_agent_memories(task_id=task_id, scope="working")

    def consolidate_task(
        self, tenant_id: str, repository: str, task_id: str,
        summary: Dict[str, Any],
    ) -> Optional[Dict[str, Any]]:
        """Archive a compact task episode, then release transient working memory."""
        if not self.enabled or not task_id:
            return None
        content = "Review task %s completed: %s" % (
            task_id,
            json.dumps(summary, ensure_ascii=False, sort_keys=True, separators=(",", ":")),
        )
        archived = self.remember(
            tenant_id, repository, "episodic", "task_summary", content,
            metadata={"summary": dict(summary)}, task_id=task_id,
            agent="agent-runtime", importance=0.65,
        )
        self.forget_working(task_id)
        return archived
