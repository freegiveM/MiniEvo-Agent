import hashlib
import json
import sqlite3
import threading
from contextlib import closing, contextmanager
from datetime import datetime, timezone
from typing import Any, Dict, Iterator, Optional

from .models import ReviewReport, TaskState, TraceEvent


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


class _ClosingConnection:
    """让 `with` 同时负责事务边界和连接归还。

    sqlite3.Connection 的 __exit__ 只做 commit/rollback，不 close。
    这个包装保留原有语义（异常回滚、正常提交），并在退出时关闭连接，
    使全部 60 余处 `with self._connect() as conn:` 调用点一次性修好，
    无需逐处改写。
    """

    def __init__(self, conn: sqlite3.Connection) -> None:
        self._conn = conn

    def __enter__(self) -> sqlite3.Connection:
        return self._conn.__enter__()

    def __exit__(self, exc_type, exc, tb) -> Optional[bool]:
        try:
            return self._conn.__exit__(exc_type, exc, tb)
        finally:
            self._conn.close()


class TaskStore:
    #: `select_evaluation_cases` 里干净样本占单次取样的份额上限。
    #: 见该方法 "## 为什么还要一个份额上限" 一节：库内比例反映的是"哪种
    #: 样本便宜"，不是线上的真实缺陷率。
    max_clean_share = 0.5

    def __init__(self, path: str):
        self.path = path
        self._lock = threading.Lock()
        self._init()

    def _connect(self):
        """返回一个用完即关的连接上下文。

        注意 sqlite3.Connection 自身的 __exit__ 只提交/回滚事务，并不关闭连接
        （见 CPython sqlite3 文档）。早先这里直接 `with self._connect() as conn:`，
        每次调用都泄漏一个文件句柄，Windows 上表现为测试 tearDown 删除临时 .db 时
        抛 PermissionError [WinError 32]。用 closing() 包一层，使 with 退出时
        既结束事务也归还句柄。
        """
        conn = sqlite3.connect(self.path, timeout=10)
        conn.row_factory = sqlite3.Row
        return _ClosingConnection(conn)

    def _init(self) -> None:
        with self._connect() as conn:
            conn.execute(
                """CREATE TABLE IF NOT EXISTS tasks (
                    id TEXT PRIMARY KEY,
                    state TEXT NOT NULL,
                    repository TEXT NOT NULL,
                    pull_request INTEGER,
                    input_json TEXT NOT NULL,
                    report_json TEXT,
                    error TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                )"""
            )
            conn.execute(
                """CREATE TABLE IF NOT EXISTS failure_cases (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    task_id TEXT NOT NULL,
                    category TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    resolved INTEGER NOT NULL DEFAULT 0,
                    created_at TEXT NOT NULL
                )"""
            )
            conn.execute(
                """CREATE TABLE IF NOT EXISTS skill_versions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    skill_name TEXT NOT NULL,
                    version INTEGER NOT NULL,
                    prompt TEXT NOT NULL,
                    score REAL NOT NULL,
                    active INTEGER NOT NULL DEFAULT 0,
                    parent_version INTEGER,
                    created_at TEXT NOT NULL,
                    UNIQUE(skill_name, version)
                )"""
            )
            conn.execute(
                """CREATE TABLE IF NOT EXISTS installations (
                    installation_id INTEGER PRIMARY KEY,
                    account_login TEXT NOT NULL,
                    created_at TEXT NOT NULL
                )"""
            )
            conn.execute(
                """CREATE TABLE IF NOT EXISTS trace_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    task_id TEXT NOT NULL,
                    step INTEGER NOT NULL,
                    state TEXT NOT NULL,
                    message TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    FOREIGN KEY(task_id) REFERENCES tasks(id)
                )"""
            )
            conn.execute(
                """CREATE TABLE IF NOT EXISTS evaluation_cases (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL UNIQUE,
                    split TEXT NOT NULL,
                    diff TEXT NOT NULL,
                    expected_json TEXT NOT NULL,
                    source TEXT NOT NULL,
                    active INTEGER NOT NULL DEFAULT 1,
                    created_at TEXT NOT NULL
                )"""
            )
            conn.execute(
                """CREATE TABLE IF NOT EXISTS evolution_runs (
                    id TEXT PRIMARY KEY,
                    skill_name TEXT NOT NULL,
                    candidate_version INTEGER NOT NULL,
                    baseline_version INTEGER,
                    decision TEXT NOT NULL,
                    candidate_score REAL NOT NULL,
                    baseline_score REAL NOT NULL,
                    metrics_json TEXT NOT NULL,
                    created_at TEXT NOT NULL
                )"""
            )
            conn.execute(
                # 消费账本：哪条 failure_case 在哪次 run 里被喂给过生成器，
                # 以及那次 run 的判决。
                #
                # 为什么需要它，而不是复用 failure_cases.resolved：
                # `resolved` 的语义是"这条反馈处理完了"，只在候选**激活**时
                # 置位（evolution.py 的 auto_propose 尾部）。但 LLM 路径固定
                # 走 activation_policy="shadow"，decision 永远是 shadow_ready
                # 而不是 activated——于是 resolved 永远不置位，同一批 case
                # 每轮重新喂一次，靠"候选提示词与上一版逐字相同"这个字符串
                # 检查兜底，第二轮开始固定返回"没有新信号"。闭环停在原地。
                #
                # 把"试过了"和"解决了"分成两张账：试过 ≠ 解决。一条被拒的
                # 候选说明这条反馈**已经被尝试过且失败了**，它不该在下一轮
                # 被当成新信号重新触发一次全量回放（几十次 LLM 调用），但它
                # 也没有被解决，仍然应该留在待分诊列表里。
                """CREATE TABLE IF NOT EXISTS evolution_attempts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    run_id TEXT NOT NULL,
                    skill_name TEXT NOT NULL,
                    failure_case_id INTEGER NOT NULL,
                    fingerprint TEXT NOT NULL,
                    decision TEXT NOT NULL,
                    reason TEXT NOT NULL DEFAULT '',
                    candidate_version INTEGER,
                    created_at TEXT NOT NULL
                )"""
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_evolution_attempts_case "
                "ON evolution_attempts(failure_case_id, created_at)"
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_evolution_attempts_fingerprint "
                "ON evolution_attempts(skill_name, fingerprint, created_at)"
            )
            # 这次尝试是**对着哪个基线**打的分。没有它，一条针对 v1 提示词
            # 被拒的记录会在提示词走到 v6 之后继续被当成反思信号回传——那条
            # "别再这么改"的结论是在一个已经不存在的基线上得出的，现在很可能
            # 已经不成立。`_prior_attempts` 用它把陈旧记录筛掉。
            #
            # 只筛反思信号，**不筛重试计数**：
            # `count_attempts_by_fingerprint` 照旧数全部历史。如果重试上限
            # 也跟着基线过期，每次激活都会给同一个根因刷新 3 次机会，那道
            # 上限就等于不存在——又一道假装在工作的门禁。
            #
            # 旧行是 NULL：无法归属基线的记录不进反思信号，不猜。
            self._ensure_column(conn, "evolution_attempts", "baseline_version", "INTEGER")
            # 这次尝试**具体改了什么**，以及分数怎么变的。
            #
            # 原先账本只存 decision + reason，于是回传给生成器的信号是
            # "这个根因上次被拒了，理由是某项受保护指标回退"——它说明不了
            # 上次试的是**哪个**改法，生成器完全可能再提一遍等价的修改，
            # 而门禁会再拒一次，把重试上限烧完。SkillOpt 的 step buffer
            # （trainer.py 的 `_format_step_buffer`）回传的是具体 edits 加
            # `score_before → score_after`，这里存的是同一份东西。
            self._ensure_column(
                conn, "evolution_attempts", "edits_json", "TEXT NOT NULL DEFAULT '{}'"
            )
            conn.execute(
                """CREATE TABLE IF NOT EXISTS skill_artifact_versions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    tenant_id TEXT NOT NULL DEFAULT 'default',
                    skill_name TEXT NOT NULL,
                    version INTEGER NOT NULL,
                    artifact_json TEXT NOT NULL,
                    artifact_sha256 TEXT NOT NULL,
                    score REAL NOT NULL,
                    active INTEGER NOT NULL DEFAULT 0,
                    parent_version INTEGER,
                    created_at TEXT NOT NULL,
                    UNIQUE(tenant_id, skill_name, version)
                )"""
            )
            conn.execute(
                """CREATE TABLE IF NOT EXISTS skill_evolution_runs (
                    id TEXT PRIMARY KEY,
                    tenant_id TEXT NOT NULL DEFAULT 'default',
                    skill_name TEXT NOT NULL,
                    candidate_version INTEGER NOT NULL,
                    baseline_version INTEGER,
                    decision TEXT NOT NULL,
                    candidate_score REAL NOT NULL,
                    baseline_score REAL NOT NULL,
                    metrics_json TEXT NOT NULL,
                    created_at TEXT NOT NULL
                )"""
            )
            self._ensure_column(
                conn, "skill_artifact_versions", "tenant_id", "TEXT NOT NULL DEFAULT 'default'"
            )
            self._ensure_column(
                conn, "skill_evolution_runs", "tenant_id", "TEXT NOT NULL DEFAULT 'default'"
            )
            self._ensure_column(conn, "tasks", "tenant_id", "TEXT NOT NULL DEFAULT 'default'")
            self._ensure_column(conn, "tasks", "cancel_requested", "INTEGER NOT NULL DEFAULT 0")
            self._ensure_column(conn, "installations", "tenant_id", "TEXT NOT NULL DEFAULT 'default'")
            conn.execute(
                """CREATE TABLE IF NOT EXISTS checkpoints (
                    task_id TEXT NOT NULL,
                    node TEXT NOT NULL,
                    status TEXT NOT NULL,
                    attempt INTEGER NOT NULL DEFAULT 1,
                    state_json TEXT NOT NULL,
                    error TEXT,
                    updated_at TEXT NOT NULL,
                    PRIMARY KEY(task_id, node),
                    FOREIGN KEY(task_id) REFERENCES tasks(id)
                )"""
            )
            conn.execute(
                """CREATE TABLE IF NOT EXISTS task_payloads (
                    task_id TEXT PRIMARY KEY,
                    diff TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    FOREIGN KEY(task_id) REFERENCES tasks(id)
                )"""
            )
            conn.execute(
                """CREATE TABLE IF NOT EXISTS agent_messages (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    task_id TEXT NOT NULL,
                    sender TEXT NOT NULL,
                    recipient TEXT NOT NULL,
                    kind TEXT NOT NULL,
                    correlation_id TEXT NOT NULL,
                    content_json TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    FOREIGN KEY(task_id) REFERENCES tasks(id)
                )"""
            )
            conn.execute(
                """CREATE TABLE IF NOT EXISTS webhook_deliveries (
                    delivery_id TEXT PRIMARY KEY,
                    tenant_id TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    payload_sha256 TEXT NOT NULL,
                    task_id TEXT,
                    received_at TEXT NOT NULL
                )"""
            )
            conn.execute(
                """CREATE TABLE IF NOT EXISTS users (
                    id TEXT PRIMARY KEY,
                    username TEXT NOT NULL UNIQUE,
                    password_hash TEXT NOT NULL,
                    active INTEGER NOT NULL DEFAULT 1,
                    created_at TEXT NOT NULL
                )"""
            )
            conn.execute(
                """CREATE TABLE IF NOT EXISTS memberships (
                    user_id TEXT NOT NULL,
                    tenant_id TEXT NOT NULL,
                    role TEXT NOT NULL,
                    PRIMARY KEY(user_id, tenant_id),
                    FOREIGN KEY(user_id) REFERENCES users(id)
                )"""
            )
            conn.execute(
                """CREATE TABLE IF NOT EXISTS repository_grants (
                    tenant_id TEXT NOT NULL,
                    repository TEXT NOT NULL,
                    auto_fix INTEGER NOT NULL DEFAULT 0,
                    PRIMARY KEY(tenant_id, repository)
                )"""
            )
            conn.execute(
                """CREATE TABLE IF NOT EXISTS audit_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    tenant_id TEXT NOT NULL,
                    actor TEXT NOT NULL,
                    action TEXT NOT NULL,
                    resource TEXT NOT NULL,
                    detail_json TEXT NOT NULL,
                    created_at TEXT NOT NULL
                )"""
            )
            conn.execute(
                """CREATE TABLE IF NOT EXISTS deployments (
                    tenant_id TEXT NOT NULL,
                    skill_name TEXT NOT NULL,
                    stable_version INTEGER,
                    candidate_version INTEGER,
                    canary_percent INTEGER NOT NULL DEFAULT 0,
                    shadow_percent INTEGER NOT NULL DEFAULT 0,
                    max_error_rate REAL NOT NULL DEFAULT 0.1,
                    min_samples INTEGER NOT NULL DEFAULT 20,
                    status TEXT NOT NULL DEFAULT 'stable',
                    samples INTEGER NOT NULL DEFAULT 0,
                    errors INTEGER NOT NULL DEFAULT 0,
                    updated_at TEXT NOT NULL,
                    PRIMARY KEY(tenant_id, skill_name)
                )"""
            )
            self._ensure_column(
                conn, "deployments", "max_disagreement_rate",
                "REAL NOT NULL DEFAULT 0.2"
            )
            self._ensure_column(
                conn, "deployments", "auto_promote", "INTEGER NOT NULL DEFAULT 0"
            )
            self._ensure_column(
                conn, "deployments", "shadow_samples", "INTEGER NOT NULL DEFAULT 0"
            )
            self._ensure_column(
                conn, "deployments", "disagreements", "INTEGER NOT NULL DEFAULT 0"
            )
            conn.execute(
                """CREATE TABLE IF NOT EXISTS release_observations (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    tenant_id TEXT NOT NULL,
                    skill_name TEXT NOT NULL,
                    task_id TEXT NOT NULL,
                    lane TEXT NOT NULL,
                    primary_json TEXT NOT NULL,
                    candidate_json TEXT,
                    disagreement REAL NOT NULL,
                    candidate_failed INTEGER NOT NULL DEFAULT 0,
                    created_at TEXT NOT NULL
                )"""
            )
            # 影子观测必须能归属到具体候选版本。`save_deployment` 只把
            # deployments 上的计数器清零，release_observations 的历史行是留着
            # 的——没有这一列，换一个候选之后上一个候选的观测会被算进新候选
            # 的晋升证据里，而且从报告上完全看不出来。旧行是 NULL：无法归属
            # 的证据不计入，不猜。
            self._ensure_column(
                conn, "release_observations", "candidate_version", "INTEGER"
            )
            # 分歧的**方向**。对称分歧率分不出"候选多报了"和"候选漏掉了
            # 基线报过的"，而这两者风险相反：前者可能是候选更强（也可能是
            # 误报），后者是能力退化。只存一个对称标量，晋升判决就没有任何
            # 依据区分它们。
            self._ensure_column(
                conn, "release_observations", "candidate_only", "INTEGER NOT NULL DEFAULT 0"
            )
            self._ensure_column(
                conn, "release_observations", "primary_only", "INTEGER NOT NULL DEFAULT 0"
            )
            conn.execute(
                """CREATE TABLE IF NOT EXISTS alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    tenant_id TEXT NOT NULL,
                    alert_key TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    message TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'open',
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    UNIQUE(tenant_id, alert_key, status)
                )"""
            )
            conn.execute(
                """CREATE TABLE IF NOT EXISTS agent_memories (
                    id TEXT PRIMARY KEY,
                    tenant_id TEXT NOT NULL,
                    repository TEXT NOT NULL,
                    task_id TEXT NOT NULL DEFAULT '',
                    agent TEXT NOT NULL DEFAULT '',
                    scope TEXT NOT NULL,
                    kind TEXT NOT NULL,
                    content TEXT NOT NULL,
                    keywords_json TEXT NOT NULL,
                    metadata_json TEXT NOT NULL,
                    importance REAL NOT NULL DEFAULT 0.5,
                    created_at TEXT NOT NULL,
                    expires_at TEXT
                )"""
            )
            conn.execute("CREATE INDEX IF NOT EXISTS idx_tasks_tenant_created ON tasks(tenant_id, created_at)")
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_agent_memories_lookup "
                "ON agent_memories(tenant_id, repository, scope, created_at)"
            )

    @staticmethod
    def _ensure_column(conn: sqlite3.Connection, table: str, column: str, declaration: str) -> None:
        columns = {row[1] for row in conn.execute("PRAGMA table_info(%s)" % table).fetchall()}
        if column not in columns:
            conn.execute("ALTER TABLE %s ADD COLUMN %s %s" % (table, column, declaration))

    def create(
        self, task_id: str, repository: str, pull_request: Optional[int],
        payload: Dict[str, Any], tenant_id: str = "default",
    ) -> None:
        now = utc_now()
        with self._lock, self._connect() as conn:
            conn.execute(
                "INSERT INTO tasks(id,state,repository,pull_request,input_json,report_json,error,"
                "created_at,updated_at,tenant_id,cancel_requested) "
                "VALUES (?, ?, ?, ?, ?, NULL, NULL, ?, ?, ?, 0)",
                (task_id, TaskState.PENDING.value, repository, pull_request,
                 json.dumps(payload), now, now, tenant_id),
            )

    def transition(self, task_id: str, event: TraceEvent) -> None:
        with self._lock, self._connect() as conn:
            conn.execute(
                "UPDATE tasks SET state = ?, updated_at = ? WHERE id = ?",
                (event.state.value, event.created_at, task_id),
            )
            conn.execute(
                "INSERT INTO trace_events(task_id, step, state, message, created_at) VALUES (?, ?, ?, ?, ?)",
                (task_id, event.step, event.state.value, event.message, event.created_at),
            )

    def succeed(self, task_id: str, report: ReviewReport, event: TraceEvent) -> None:
        with self._lock, self._connect() as conn:
            conn.execute(
                "UPDATE tasks SET state = ?, report_json = ?, updated_at = ? WHERE id = ?",
                (TaskState.SUCCESS.value, json.dumps(report.to_dict(), ensure_ascii=False), event.created_at, task_id),
            )
            conn.execute(
                "INSERT INTO trace_events(task_id, step, state, message, created_at) VALUES (?, ?, ?, ?, ?)",
                (task_id, event.step, event.state.value, event.message, event.created_at),
            )

    def fail(self, task_id: str, error: str, event: TraceEvent) -> None:
        with self._lock, self._connect() as conn:
            conn.execute(
                "UPDATE tasks SET state = ?, error = ?, updated_at = ? WHERE id = ?",
                (TaskState.FAILED.value, error[:2000], event.created_at, task_id),
            )
            conn.execute(
                "INSERT INTO trace_events(task_id, step, state, message, created_at) VALUES (?, ?, ?, ?, ?)",
                (task_id, event.step, event.state.value, event.message, event.created_at),
            )

    def get(self, task_id: str, tenant_id: Optional[str] = None) -> Optional[Dict[str, Any]]:
        with self._connect() as conn:
            if tenant_id is None:
                row = conn.execute("SELECT * FROM tasks WHERE id = ?", (task_id,)).fetchone()
            else:
                row = conn.execute(
                    "SELECT * FROM tasks WHERE id = ? AND tenant_id = ?", (task_id, tenant_id)
                ).fetchone()
            if row is None:
                return None
            events = conn.execute(
                "SELECT step, state, message, created_at FROM trace_events WHERE task_id = ? ORDER BY id", (task_id,)
            ).fetchall()
            messages = conn.execute(
                "SELECT sender,recipient,kind,correlation_id,content_json,created_at "
                "FROM agent_messages WHERE task_id=? ORDER BY id", (task_id,)
            ).fetchall()
        value = dict(row)
        value["input"] = json.loads(value.pop("input_json"))
        report_json = value.pop("report_json")
        value["report"] = json.loads(report_json) if report_json else None
        value["trace"] = [dict(item) for item in events]
        value["collaboration"] = []
        for message in messages:
            item = dict(message)
            item["content"] = json.loads(item.pop("content_json"))
            value["collaboration"].append(item)
        return value

    def record_agent_message(self, task_id: str, message: Dict[str, Any]) -> None:
        with self._lock, self._connect() as conn:
            conn.execute(
                "INSERT INTO agent_messages(task_id,sender,recipient,kind,correlation_id,"
                "content_json,created_at) VALUES (?,?,?,?,?,?,?)",
                (task_id, message["sender"], message["recipient"], message["kind"],
                 message.get("correlation_id", ""),
                 json.dumps(message.get("content", {}), ensure_ascii=False), utc_now()),
            )

    def save_agent_memory(self, memory: Dict[str, Any]) -> Dict[str, Any]:
        with self._lock, self._connect() as conn:
            conn.execute(
                "INSERT INTO agent_memories(id,tenant_id,repository,task_id,agent,scope,kind,"
                "content,keywords_json,metadata_json,importance,created_at,expires_at) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET "
                "importance=MAX(agent_memories.importance,excluded.importance),"
                "expires_at=excluded.expires_at",
                (
                    memory["id"], memory["tenant_id"], memory["repository"],
                    memory.get("task_id", ""), memory.get("agent", ""), memory["scope"],
                    memory["kind"], memory["content"],
                    json.dumps(memory.get("keywords", []), ensure_ascii=False),
                    json.dumps(memory.get("metadata", {}), ensure_ascii=False),
                    float(memory.get("importance", 0.5)), memory["created_at"],
                    memory.get("expires_at"),
                ),
            )
            row = conn.execute(
                "SELECT * FROM agent_memories WHERE id=?", (memory["id"],)
            ).fetchone()
        return self._memory_from_row(row)

    def list_agent_memories(
        self, tenant_id: str, repository: str, scopes: tuple,
        limit: int = 100,
    ) -> list:
        placeholders = ",".join("?" for _ in scopes)
        params = [tenant_id, repository, *scopes, utc_now(), max(1, min(limit, 500))]
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM agent_memories WHERE tenant_id=? AND repository=? "
                "AND scope IN (%s) AND (expires_at IS NULL OR expires_at>?) "
                "ORDER BY importance DESC,created_at DESC LIMIT ?" % placeholders,
                params,
            ).fetchall()
        return [self._memory_from_row(row) for row in rows]

    def delete_agent_memories(self, task_id: str = "", scope: str = "") -> int:
        clauses = []
        params = []
        if task_id:
            clauses.append("task_id=?")
            params.append(task_id)
        if scope:
            clauses.append("scope=?")
            params.append(scope)
        if not clauses:
            raise ValueError("memory deletion requires task_id or scope")
        with self._lock, self._connect() as conn:
            cursor = conn.execute(
                "DELETE FROM agent_memories WHERE " + " AND ".join(clauses), params
            )
            return cursor.rowcount

    def purge_expired_agent_memories(self) -> int:
        with self._lock, self._connect() as conn:
            cursor = conn.execute(
                "DELETE FROM agent_memories WHERE expires_at IS NOT NULL AND expires_at<=?",
                (utc_now(),),
            )
            return cursor.rowcount

    @staticmethod
    def _memory_from_row(row) -> Dict[str, Any]:
        value = dict(row)
        value["keywords"] = json.loads(value.pop("keywords_json"))
        value["metadata"] = json.loads(value.pop("metadata_json"))
        return value

    def list_tasks(self, limit: int = 50, tenant_id: Optional[str] = None) -> list:
        with self._connect() as conn:
            if tenant_id is None:
                rows = conn.execute(
                    "SELECT id,state,repository,pull_request,error,created_at,updated_at,tenant_id "
                    "FROM tasks ORDER BY created_at DESC LIMIT ?", (max(1, min(limit, 200)),)
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT id,state,repository,pull_request,error,created_at,updated_at,tenant_id "
                    "FROM tasks WHERE tenant_id=? ORDER BY created_at DESC LIMIT ?",
                    (tenant_id, max(1, min(limit, 200))),
                ).fetchall()
        return [dict(item) for item in rows]

    def find_latest_review_task(
        self, repository: str, pull_request: int, tenant_id: Optional[str] = None,
        state: str = "SUCCESS",
    ) -> Optional[Dict[str, Any]]:
        """找这个 PR 最近一次成功的审查任务。

        用于把 PR 关闭/合并事件接回它当初的审查报告。取**最近一次**而不是
        全部：`synchronize` 会为同一个 PR 反复建任务，早先几轮审的是已经
        被后续 commit 改掉的代码，拿它们推断"报告对不对"是错的。

        state 默认 SUCCESS——失败的任务没有报告可比对。
        """
        query = (
            "SELECT id FROM tasks WHERE repository=? AND pull_request=? AND state=?"
        )
        params: list = [repository, pull_request, state]
        if tenant_id is not None:
            query += " AND tenant_id=?"
            params.append(tenant_id)
        query += " ORDER BY created_at DESC, rowid DESC LIMIT 1"
        with self._connect() as conn:
            row = conn.execute(query, params).fetchone()
        if row is None:
            return None
        return self.get(row["id"], tenant_id)

    def count_failure_cases_by_category(
        self, tenant_id: Optional[str] = None, unresolved_only: bool = False,
    ) -> Dict[str, int]:
        """按 category 计数。用于报数时把推断来源与人工来源分开看。"""
        query = "SELECT f.category AS category, COUNT(*) AS n FROM failure_cases f"
        params: list = []
        clauses = []
        if tenant_id is not None:
            query += " JOIN tasks t ON t.id=f.task_id"
            clauses.append("t.tenant_id = ?")
            params.append(tenant_id)
        if unresolved_only:
            clauses.append("f.resolved = 0")
        if clauses:
            query += " WHERE " + " AND ".join(clauses)
        query += " GROUP BY f.category"
        with self._connect() as conn:
            rows = conn.execute(query, params).fetchall()
        return {item["category"]: int(item["n"]) for item in rows}

    def record_failure_case(self, task_id: str, category: str, payload: Dict[str, Any]) -> None:
        with self._lock, self._connect() as conn:
            conn.execute(
                "INSERT INTO failure_cases(task_id, category, payload_json, created_at) VALUES (?, ?, ?, ?)",
                (task_id, category, json.dumps(payload, ensure_ascii=False), utc_now()),
            )

    def list_failure_cases(
        self, unresolved_only: bool = False, limit: int = 100,
        tenant_id: Optional[str] = None,
    ) -> list:
        query = "SELECT f.* FROM failure_cases f"
        params = []
        clauses = []
        if tenant_id is not None:
            query += " JOIN tasks t ON t.id=f.task_id"
            clauses.append("t.tenant_id = ?")
            params.append(tenant_id)
        if unresolved_only:
            clauses.append("f.resolved = 0")
        if clauses:
            query += " WHERE " + " AND ".join(clauses)
        query += " ORDER BY f.id DESC LIMIT ?"
        params.append(max(1, min(limit, 500)))
        with self._connect() as conn:
            rows = conn.execute(query, params).fetchall()
        values = []
        for row in rows:
            item = dict(row)
            item["payload"] = json.loads(item.pop("payload_json"))
            values.append(item)
        return values

    def list_task_failure_cases(
        self, task_id: str, tenant_id: Optional[str] = None,
    ) -> list:
        query = "SELECT f.* FROM failure_cases f"
        params = []
        if tenant_id is not None:
            query += " JOIN tasks t ON t.id=f.task_id"
            query += " WHERE f.task_id=? AND t.tenant_id=?"
            params.extend([task_id, tenant_id])
        else:
            query += " WHERE f.task_id=?"
            params.append(task_id)
        query += " ORDER BY f.id DESC"
        with self._connect() as conn:
            rows = conn.execute(query, params).fetchall()
        values = []
        for row in rows:
            item = dict(row)
            item["payload"] = json.loads(item.pop("payload_json"))
            values.append(item)
        return values

    def resolve_failure_cases(self, case_ids: list) -> None:
        ids = [int(value) for value in case_ids]
        if not ids:
            return
        placeholders = ",".join("?" for _ in ids)
        with self._lock, self._connect() as conn:
            conn.execute(
                "UPDATE failure_cases SET resolved = 1 WHERE id IN (%s)" % placeholders,
                ids,
            )

    def save_evaluation_case(
        self, name: str, split: str, diff: str, expected: list,
        source: str = "manual", active: bool = True,
    ) -> Dict[str, Any]:
        expected_json = json.dumps(expected, ensure_ascii=False)
        with self._lock, self._connect() as conn:
            existing = conn.execute(
                "SELECT * FROM evaluation_cases WHERE name = ?", (name,)
            ).fetchone()
            if existing is not None:
                if (
                    existing["split"] != split
                    or existing["diff"] != diff
                    or json.loads(existing["expected_json"]) != expected
                ):
                    raise ValueError(
                        "evaluation case names are immutable; use a new name for revised content"
                    )
                row = existing
            else:
                conn.execute(
                    "INSERT INTO evaluation_cases(name,split,diff,expected_json,source,active,created_at) "
                    "VALUES (?,?,?,?,?,?,?)",
                    (name, split, diff, expected_json, source, int(active), utc_now()),
                )
                row = conn.execute(
                    "SELECT * FROM evaluation_cases WHERE name = ?", (name,)
                ).fetchone()
        value = dict(row)
        value["expected"] = json.loads(value.pop("expected_json"))
        value["active"] = bool(value["active"])
        return value

    def list_evaluation_cases(
        self, split: Optional[str] = None, active_only: bool = True, limit: int = 100,
    ) -> list:
        clauses = []
        params = []
        if split:
            clauses.append("split = ?")
            params.append(split)
        if active_only:
            clauses.append("active = 1")
        query = "SELECT * FROM evaluation_cases"
        if clauses:
            query += " WHERE " + " AND ".join(clauses)
        query += " ORDER BY id LIMIT ?"
        params.append(max(1, min(limit, 500)))
        with self._connect() as conn:
            rows = conn.execute(query, params).fetchall()
        values = []
        for row in rows:
            value = dict(row)
            value["expected"] = json.loads(value.pop("expected_json"))
            value["active"] = bool(value["active"])
            values.append(value)
        return values

    def select_evaluation_cases(
        self, split: Optional[str] = None, active_only: bool = True,
        limit: int = 100,
    ) -> list:
        """按"带缺陷 / 干净"分层取样，而不是 `ORDER BY id LIMIT n`。

        ## 为什么必须分层

        `list_evaluation_cases` 按 id 截断。`evaluation_cases` 里干净样本
        （`expected_json = '[]'`）是后灌进去的，id 必然排在已有正样本之后，
        于是 `LIMIT 5` 永远取不到它们——**把 78 条 clean 语料入库，
        `clean_cases` 依然会是 0**。实测过：库里 id 24/25 本来就是干净样本，
        而 `_propose` 拿到的 5 条全是 id 1-5 的缺陷样本。

        `clean_accuracy`（≈ 1 − FPR）在打分公式里占权重 0.20，且
        `_protected_metrics` 只在 `baseline["clean_cases"] > 0` 时才把它列为
        受保护指标。分母为 0 时这两处一起失效：**进化回路只能看见"漏报变少
        了没"，看不见"误报变多了没"**，于是候选可以靠多报把 recall 顶上去
        而不受惩罚。实测的第一轮候选正是这个形状：recall 0.6 → 0.8，代价是
        predicted_findings 7 → 9。

        ## 取样口径

        两层各按 id 升序取（**不随机**）：评测集变了要能解释成"库里内容变了"，
        而不是"这次抽样抽到了别的"。`_propose` 会把
        `validation_dataset_fingerprint` 落盘，随机取样会让同一个库连续两轮
        的指纹不同，指纹就失去意义了。

        名额按两层的实际存量比例分配，但每一层只要非空就至少保 1 条：
        比例分配在 `limit` 很小时会把少数层直接抹成 0（5 × 78/173 = 2.25，
        向下取整还行，但 3 × 20/173 = 0.34 → 0），而少一层就等于那道门禁
        无声失效——这正是要修的毛病本身。

        ## 为什么还要一个份额上限

        库内比例反映的**不是线上真实缺陷率，而是"哪种样本便宜"**：干净 PR
        可以批量抓（`real-pr-clean-v1.jsonl` 有 78 条），人工确认过的缺陷
        样本很贵（20 条）。纯按比例取样时 `limit=20` 会取出 4 条缺陷 + 15 条
        干净，recall 的步长变成 0.25，precision/recall 退化成噪声——**那等于
        用"补上误报侧的分母"换掉了漏报侧的分母**，两头都量不准。

        所以干净层另受 `max_clean_share`（0.5）约束。代价是缺陷层取完后
        返回条数会少于 `limit`（20 缺陷 + 78 干净、`limit=98` 时只返回 62
        条）：**这是诚实结果，不是缺陷**。硬凑到 `limit` 只能靠突破上限，
        那会把测出来的分数重新变成干净样本的分数。

        `limit=1` 时两层各留 1 条必然超限，退回旧口径——1 条的评测集本来
        就量不出两个方向。
        """
        clauses = []
        params: List[Any] = []
        if split:
            clauses.append("split = ?")
            params.append(split)
        if active_only:
            clauses.append("active = 1")
        where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
        limit = max(1, min(limit, 500))

        def fetch(extra: str) -> list:
            query = "SELECT * FROM evaluation_cases" + where
            query += (" AND " if clauses else " WHERE ") + extra
            query += " ORDER BY id"
            with self._connect() as conn:
                return [dict(row) for row in conn.execute(query, params).fetchall()]

        # "干净"的判定必须和 `_score` 里的 `int(not expected_items)` 对齐：
        # 那边看的是反序列化后的空列表，这里只能看存储形态。两者一致的前提是
        # `expected_json` 恒为合法 JSON——由 schema 的 NOT NULL 加
        # `save_evaluation_case` 的 `json.dumps` 共同保证。
        #
        # 刻意**不**在这里加 `IS NULL OR TRIM(...) = ''` 之类的兜底：那种行
        # 会在 hydration 的 `json.loads` 就崩掉（两条取样路径都一样），根本
        # 走不到分层判定，兜底分支只会看起来在防守而实际永不生效。要防就在
        # 写入侧防。见 test_a_corrupt_expected_json_fails_the_same_way_on_both_paths。
        positive = fetch("expected_json != '[]'")
        clean = fetch("expected_json = '[]'")
        if not positive:
            # 没有缺陷层时两级分层都无从谈起，退回原口径，行为逐字节不变。
            return self.list_evaluation_cases(split, active_only, limit)
        if not clean:
            # 干净层为空时"缺陷 / 干净"这一级没得分，但**严重度那一级仍然
            # 要分**。两级管的是两个互相独立的分母：外层给 `clean_accuracy`，
            # 内层给 `high_severity_recall`。在这里一并退回平铺截断，等于让
            # 后者的分母重新取决于"库里有没有干净样本"——一个与严重度毫无
            # 关系的条件。holdout 就差点栽在这上面：缺陷条数涨到 110，
            # 高危分母在 limit=20 下仍然是 1。
            return self._hydrate(self._take_positive(positive, limit))
        if limit < 2:
            # 预算只有 1 条时两层各留 1 条必然超限，而超限比少一层更糟：
            # limit 是调用方给的预算，不是建议值。1 条的评测集本来就量不出
            # 误报/漏报两个方向，这里退回旧口径而不是偷偷返回 2 条。
            return self.list_evaluation_cases(split, active_only, limit)

        total = len(positive) + len(clean)
        if limit >= total:
            # 预算够装下整张表时没有任何取舍要做，全给。
            #
            # 这一支是必须的：份额上限的职责是**分配稀缺预算**，不是删减语料。
            # 少了它，调用方明明要"全部 20 条"却拿到 12 条，
            # `holdout_dataset_ready`（比较 len(cases) 与 min_holdout_cases）
            # 就会失败——rejection_proof 正是这么被打断的，它按
            # `max_cases=len(cases)` 请求全集。取样在这种情形下悄悄丢掉 8 条，
            # 等于对数据集规模说谎。
            return self.list_evaluation_cases(split, active_only, limit)

        # 名额按存量比例分配，但干净层的份额另设上限。
        #
        # 库内比例反映的**不是线上真实缺陷率，而是"哪种样本便宜"**：干净 PR
        # 可以批量抓（78 条），人工确认过的缺陷样本很贵（20 条）。纯按比例时
        # limit=20 会取出 4 缺陷 + 15 干净，recall 的步长变成 0.25，
        # precision/recall 退化成噪声——那等于用"补上误报侧的分母"换掉了
        # 漏报侧的分母，两头都量不准。
        share = min(len(clean) / total, self.max_clean_share)
        clean_quota = max(1, min(len(clean), int(limit * share)))
        positive_quota = max(1, min(len(positive), limit - clean_quota))
        # 干净层不得超过**实际取到的**缺陷条数。按预算的一半算上限在缺陷层
        # 存量不足时会失效（20 缺陷 + 78 干净、limit=98 时取出 20 缺陷 +
        # 49 干净，71% 干净），而那正是这个上限本该拦住的形态。
        clean_quota = min(clean_quota, positive_quota)

        return self._hydrate(
            self._take_positive(positive, positive_quota) + clean[:clean_quota]
        )

    @staticmethod
    def _hydrate(selected: list) -> list:
        """按 id 排序并反序列化，口径与 `list_evaluation_cases` 一致。

        排序放在这里而不是各个取样分支里：分层取样天然打乱顺序（缺陷层
        与干净层、普通与高危各自按 id 取，拼起来就不是全局有序了），而
        `_propose` 的数据集指纹按返回顺序算。少排一次，同一套样本会因为
        拼接次序不同而算出不同的指纹。
        """
        values = []
        for row in sorted(selected, key=lambda item: item["id"]):
            value = dict(row)
            value["expected"] = json.loads(value.pop("expected_json"))
            value["active"] = bool(value["active"])
            values.append(value)
        return values

    #: `expected.min_severity` 落在这两档时算高危样本，与
    #: `evaluation_harness` 里 `high_severity_recall` 的口径一致。
    high_severities = ("high", "critical")

    @staticmethod
    def _has_high_severity(row: dict) -> bool:
        """这条样本的期望里有没有 high/critical。

        只能看存储形态（`expected_json` 还没反序列化）。解析失败不在这里
        兜——坏行会在 hydration 的 `json.loads` 崩掉，两条取样路径一样，
        在这里 try/except 只会把一个写入侧的缺陷藏起来。
        """
        for item in json.loads(row["expected_json"]):
            if str(item.get("min_severity", "")).lower() in TaskStore.high_severities:
                return True
        return False

    def _take_positive(self, positive: list, quota: int) -> list:
        """在缺陷层内部再按严重度分层取。

        ## 为什么缺陷层还要再分一层

        这是干净样本那个毛病的**同形复发**，只是换了一个维度。补进 holdout
        的高危样本 id 排在最后（实测 id 182-214，而缺陷层从 id 26 起），
        `positive[:quota]` 按 id 截断时永远取不到它们：holdout 缺陷分母从
        1 涨到 110 之后，`high_severity_denominator` 在 `limit=20` 下**仍然
        是 1**。

        后果和 `clean_accuracy` 那次一样，只是更隐蔽：
        `high_severity_recall` 是 `_protected_metrics` 里**无条件**列入的
        受保护指标（不像 `clean_accuracy` 有 `if baseline["clean_cases"]`
        把关），分母为 0 时 `_metric_non_regressing` 按"本来没测过，无从
        回退"放行，于是它恒通过。`_non_regression_report` 的
        `unmeasurable` 会如实列出这一项——但那是报告，不是门禁。

        分母为 1 比 0 更难发现：指标照常打印一个 0.0/1.0 的读数，看不出
        它只有两档。

        ## 取样口径

        与外层完全一致：两层各按 id 升序取（不随机，指纹要能解释），
        非空的层至少保 1 条，且高危层不超过实际取到的普通缺陷条数——
        高危样本目前全部来自 `mutation-v1` 的 weakened-guard 单一算子，
        让它占满缺陷层会把 recall 变成"对减弱守卫的敏感度"。
        """
        high = [row for row in positive if self._has_high_severity(row)]
        rest = [row for row in positive if not self._has_high_severity(row)]
        if not high or not rest or quota < 2:
            # 只有一层、或预算装不下两层各 1 条时，退回原口径。
            return positive[:quota]

        high_quota = max(1, min(len(high), int(quota * len(high) / len(positive))))
        rest_quota = max(1, min(len(rest), quota - high_quota))
        # 高危层不得超过**实际取到的**普通缺陷条数，理由同 `max_clean_share`：
        # 按预算算的上限在普通层存量不足时会失效。
        high_quota = min(high_quota, rest_quota)
        return rest[:rest_quota] + high[:high_quota]

    def save_evolution_run(self, run: Dict[str, Any]) -> Dict[str, Any]:
        with self._lock, self._connect() as conn:
            conn.execute(
                "INSERT INTO evolution_runs(id,skill_name,candidate_version,baseline_version,decision,"
                "candidate_score,baseline_score,metrics_json,created_at) VALUES (?,?,?,?,?,?,?,?,?)",
                (
                    run["id"], run["skill_name"], run["candidate_version"], run.get("baseline_version"),
                    run["decision"], run["candidate_score"], run["baseline_score"],
                    json.dumps(run["metrics"], ensure_ascii=False), run["created_at"],
                ),
            )
        return run

    def list_evolution_runs(
        self, limit: int = 50, skill_name: Optional[str] = None,
    ) -> list:
        """按时间倒序列出评测记录。

        `skill_name` 是可选过滤，默认 None = 全部，与本参数加入之前的行为
        一致。档案构建（archive.py）必须传它：不同 skill 的版本号各自从 1
        开始编号，不过滤的话 `llm-review` 的 v3 会跟另一个 skill 的 v3 撞
        在一起，逐样本分数表被污染，而这种污染在报告里看不出来。
        """
        clause = " WHERE skill_name = ?" if skill_name else ""
        params: tuple = (skill_name,) if skill_name else ()
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM evolution_runs" + clause
                + " ORDER BY created_at DESC LIMIT ?",
                params + (max(1, min(limit, 200)),),
            ).fetchall()
        values = []
        for row in rows:
            value = dict(row)
            value["metrics"] = json.loads(value.pop("metrics_json"))
            values.append(value)
        return values

    def update_evolution_run(self, run_id: str, decision: str, metrics: Dict[str, Any]) -> bool:
        with self._lock, self._connect() as conn:
            cursor = conn.execute(
                "UPDATE evolution_runs SET decision = ?, metrics_json = ? WHERE id = ?",
                (decision, json.dumps(metrics, ensure_ascii=False), run_id),
            )
            return cursor.rowcount == 1

    def record_evolution_attempts(
        self, run_id: str, skill_name: str, decision: str, reason: str,
        candidate_version: Optional[int], cases: list,
        baseline_version: Optional[int] = None,
        edits: Optional[Dict[str, Any]] = None,
    ) -> int:
        """记账：这批 failure_case 在这次 run 里被尝试过，判决是什么。

        `cases` 是 (failure_case_id, fingerprint) 的序列。一次写入一批，
        同一个事务——半批落盘会让下一轮把剩下那半当成"从未尝试过"。

        `baseline_version` 是这次判决对着哪个基线打的分，`edits` 是这次
        具体改了什么（见建表处那两列的注释）。两者都默认 None/空：调用方
        没提供时写 NULL 与 `{}`，而 `list_reflection_attempts` 会把
        baseline 为 NULL 的行排除在反思信号之外——猜一个基线号的后果是把
        陈旧结论当成当前有效的，那比没有信号更坏。
        """
        rows = [
            (run_id, skill_name, int(case_id), str(fingerprint), decision,
             str(reason or "")[:1000], candidate_version, utc_now(),
             baseline_version,
             json.dumps(edits or {}, ensure_ascii=False))
            for case_id, fingerprint in cases
        ]
        if not rows:
            return 0
        with self._lock, self._connect() as conn:
            conn.executemany(
                "INSERT INTO evolution_attempts(run_id,skill_name,failure_case_id,"
                "fingerprint,decision,reason,candidate_version,created_at,"
                "baseline_version,edits_json) "
                "VALUES (?,?,?,?,?,?,?,?,?,?)",
                rows,
            )
        return len(rows)

    def list_attempted_failure_case_ids(self, skill_name: str) -> set:
        """已经被喂给过生成器的 failure_case id。

        不按 decision 过滤：被拒的候选说明这条反馈**试过且失败了**，
        它同样不该在下一轮被当成新信号重新触发一次全量回放。想重试的话
        是一个显式动作（人工重开），不是默认行为。
        """
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT DISTINCT failure_case_id FROM evolution_attempts WHERE skill_name = ?",
                (skill_name,),
            ).fetchall()
        return {int(row["failure_case_id"]) for row in rows}

    def count_attempts_by_fingerprint(self, skill_name: str) -> Dict[str, int]:
        """每个根因指纹被尝试过多少次（去重到 run 级）。

        用于 DGM 式的选亲：一个反复尝试反复失败的根因，说明"改提示词"
        这个动作对它无效，不该无限重试。

        **不按 baseline_version 过滤，这是刻意的。** 反思信号会随基线过期
        （见 `list_reflection_attempts`），重试计数不会：这个数回答的是
        "在这个根因上一共花过多少次全量回放"，那笔钱不会因为提示词换了版本
        就退回来。跟着基线过期的话，每激活一个新版本就等于给所有根因重置
        额度，`max_attempts_per_root_cause` 名存实亡。
        """
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT fingerprint, COUNT(DISTINCT run_id) AS n FROM evolution_attempts "
                "WHERE skill_name = ? GROUP BY fingerprint",
                (skill_name,),
            ).fetchall()
        return {str(row["fingerprint"]): int(row["n"]) for row in rows}

    def list_evolution_attempts(self, skill_name: str, limit: int = 200) -> list:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM evolution_attempts WHERE skill_name = ? "
                "ORDER BY id DESC LIMIT ?",
                (skill_name, max(1, min(limit, 1000))),
            ).fetchall()
        return [dict(row) for row in rows]

    def list_reflection_attempts(
        self, skill_name: str, baseline_version: Optional[int], limit: int = 200,
    ) -> list:
        """还**能当反思信号**用的账本行：只取同一基线上打的分。

        与 `list_evolution_attempts` 的区别不是过滤条件的松紧，是用途：
        那个方法是审计视图（全部历史，谁都不该被藏起来），这个是喂回生成器
        的信号。一条针对 v1 提示词被拒的记录，在提示词走到 v6 之后已经不是
        证据了——"别再这么改"是在一个不存在的基线上得出的结论，当前基线里
        可能压根没有那段文本。继续回传它有两个坏处：挤占 token 预算，以及
        把生成器往一个已经无效的禁区上引。

        `baseline_version` 为 None 时（第一轮，还没有 active 版本）返回空：
        没有基线就没有"同一基线"可言。行上 `baseline_version` 为 NULL 的
        （本列加入之前写的老行）同样不返回——它们归属不到任何基线，当成
        当前有效会把陈旧结论伪装成新鲜的。

        **这个过滤绝不影响重试上限。** `count_attempts_by_fingerprint`
        照旧数全部历史行。见建表处那段注释：让上限也跟着基线过期，等于
        每次激活刷新一次重试额度，那道门禁就名存实亡了。
        """
        if baseline_version is None:
            return []
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM evolution_attempts "
                "WHERE skill_name = ? AND baseline_version = ? "
                "ORDER BY id DESC LIMIT ?",
                (skill_name, int(baseline_version), max(1, min(limit, 1000))),
            ).fetchall()
        return [dict(row) for row in rows]

    def save_skill_version(
        self, skill_name: str, prompt: str, score: float, activate: bool = False,
        parent_version: Optional[int] = None,
    ) -> Dict[str, Any]:
        """存一个新版本。

        `parent_version` 显式传入时记它，否则回落到当前 active 版本——后者
        是本参数加入之前的唯一行为。

        为什么需要显式传：档案选亲（archive.py）之后，候选的基线可能不是
        active 版本。仍然记 active 当亲本会让血统记录说谎，而 `parent_version`
        是事后重建搜索路径的唯一依据——记错了，"这个提示词是从哪一支演化
        来的"就永远查不回来了。
        """
        with self._lock, self._connect() as conn:
            row = conn.execute(
                "SELECT COALESCE(MAX(version), 0) AS version FROM skill_versions WHERE skill_name = ?", (skill_name,)
            ).fetchone()
            version = int(row["version"]) + 1
            if parent_version is None:
                parent = self.get_active_skill_version(skill_name)
                parent_version = parent["version"] if parent else None
            if activate:
                conn.execute("UPDATE skill_versions SET active = 0 WHERE skill_name = ?", (skill_name,))
            conn.execute(
                "INSERT INTO skill_versions(skill_name, version, prompt, score, active, parent_version, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (skill_name, version, prompt, score, int(activate), parent_version, utc_now()),
            )
        return {
            "skill_name": skill_name, "version": version, "score": score,
            "active": activate, "parent_version": parent_version,
        }

    def get_active_skill_version(self, skill_name: str) -> Optional[Dict[str, Any]]:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM skill_versions WHERE skill_name = ? AND active = 1 ORDER BY version DESC LIMIT 1",
                (skill_name,),
            ).fetchone()
        return dict(row) if row else None

    def list_skill_versions(self, skill_name: str) -> list:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM skill_versions WHERE skill_name = ? ORDER BY version DESC", (skill_name,)
            ).fetchall()
        return [dict(item) for item in rows]

    def activate_skill_version(self, skill_name: str, version: int) -> bool:
        with self._lock, self._connect() as conn:
            exists = conn.execute(
                "SELECT 1 FROM skill_versions WHERE skill_name = ? AND version = ?", (skill_name, version)
            ).fetchone()
            if not exists:
                return False
            conn.execute("UPDATE skill_versions SET active = 0 WHERE skill_name = ?", (skill_name,))
            conn.execute(
                "UPDATE skill_versions SET active = 1 WHERE skill_name = ? AND version = ?", (skill_name, version)
            )
        return True

    def save_skill_artifact(
        self, skill_name: str, artifact: Dict[str, Any], score: float,
        activate: bool = False, tenant_id: str = "default",
    ) -> Dict[str, Any]:
        artifact_json = json.dumps(
            artifact, ensure_ascii=False, sort_keys=True, separators=(",", ":")
        )
        artifact_sha256 = hashlib.sha256(artifact_json.encode("utf-8")).hexdigest()
        with self._lock, self._connect() as conn:
            row = conn.execute(
                "SELECT COALESCE(MAX(version),0) AS version FROM skill_artifact_versions "
                "WHERE tenant_id=? AND skill_name=?", (tenant_id, skill_name),
            ).fetchone()
            version = int(row["version"]) + 1
            parent = conn.execute(
                "SELECT version FROM skill_artifact_versions WHERE tenant_id=? AND skill_name=? "
                "AND active=1 ORDER BY version DESC LIMIT 1", (tenant_id, skill_name),
            ).fetchone()
            if activate:
                conn.execute(
                    "UPDATE skill_artifact_versions SET active=0 WHERE tenant_id=? AND skill_name=?",
                    (tenant_id, skill_name),
                )
            created_at = utc_now()
            conn.execute(
                "INSERT INTO skill_artifact_versions(tenant_id,skill_name,version,artifact_json,"
                "artifact_sha256,score,active,parent_version,created_at) VALUES (?,?,?,?,?,?,?,?,?)",
                (tenant_id, skill_name, version, artifact_json, artifact_sha256, float(score),
                 int(activate), parent["version"] if parent else None, created_at),
            )
        return {
            "tenant_id": tenant_id, "skill_name": skill_name, "version": version, "score": float(score),
            "active": activate, "parent_version": parent["version"] if parent else None,
            "artifact_sha256": artifact_sha256, "created_at": created_at,
        }

    @staticmethod
    def _decode_skill_artifact(row) -> Dict[str, Any]:
        value = dict(row)
        value["artifact"] = json.loads(value.pop("artifact_json"))
        value["active"] = bool(value["active"])
        return value

    def get_active_skill_artifact(
        self, skill_name: str, tenant_id: str = "default",
    ) -> Optional[Dict[str, Any]]:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM skill_artifact_versions WHERE tenant_id=? AND skill_name=? "
                "AND active=1 ORDER BY version DESC LIMIT 1", (tenant_id, skill_name),
            ).fetchone()
        return self._decode_skill_artifact(row) if row else None

    def list_active_skill_artifacts(self, tenant_id: str = "default") -> list:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM skill_artifact_versions WHERE tenant_id=? AND active=1 "
                "ORDER BY skill_name", (tenant_id,)
            ).fetchall()
        return [self._decode_skill_artifact(row) for row in rows]

    def list_skill_artifact_versions(
        self, skill_name: str, tenant_id: str = "default",
    ) -> list:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM skill_artifact_versions WHERE tenant_id=? AND skill_name=? "
                "ORDER BY version DESC", (tenant_id, skill_name),
            ).fetchall()
        return [self._decode_skill_artifact(row) for row in rows]

    def activate_skill_artifact(
        self, skill_name: str, version: int, tenant_id: str = "default",
    ) -> bool:
        with self._lock, self._connect() as conn:
            exists = conn.execute(
                "SELECT 1 FROM skill_artifact_versions v WHERE v.tenant_id=? "
                "AND v.skill_name=? AND v.version=? AND (v.active=1 OR EXISTS ("
                "SELECT 1 FROM skill_evolution_runs r WHERE r.tenant_id=v.tenant_id "
                "AND r.skill_name=v.skill_name AND r.candidate_version=v.version "
                "AND r.decision='activated'))",
                (tenant_id, skill_name, version),
            ).fetchone()
            if not exists:
                return False
            conn.execute(
                "UPDATE skill_artifact_versions SET active=0 WHERE tenant_id=? AND skill_name=?",
                (tenant_id, skill_name),
            )
            conn.execute(
                "UPDATE skill_artifact_versions SET active=1 WHERE tenant_id=? AND skill_name=? "
                "AND version=?", (tenant_id, skill_name, version),
            )
        return True

    def save_skill_evolution_run(self, run: Dict[str, Any]) -> Dict[str, Any]:
        with self._lock, self._connect() as conn:
            conn.execute(
                "INSERT INTO skill_evolution_runs(id,tenant_id,skill_name,candidate_version,baseline_version,"
                "decision,candidate_score,baseline_score,metrics_json,created_at) "
                "VALUES (?,?,?,?,?,?,?,?,?,?)",
                (run["id"], run.get("tenant_id", "default"), run["skill_name"], run["candidate_version"],
                 run.get("baseline_version"), run["decision"], run["candidate_score"],
                 run["baseline_score"], json.dumps(run["metrics"], ensure_ascii=False),
                 run["created_at"]),
            )
        return run

    def list_skill_evolution_runs(
        self, limit: int = 50, tenant_id: Optional[str] = None,
    ) -> list:
        with self._connect() as conn:
            if tenant_id is None:
                rows = conn.execute(
                    "SELECT * FROM skill_evolution_runs ORDER BY created_at DESC LIMIT ?",
                    (max(1, min(limit, 200)),),
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM skill_evolution_runs WHERE tenant_id=? "
                    "ORDER BY created_at DESC LIMIT ?",
                    (tenant_id, max(1, min(limit, 200))),
                ).fetchall()
        values = []
        for row in rows:
            value = dict(row)
            value["metrics"] = json.loads(value.pop("metrics_json"))
            values.append(value)
        return values

    def save_installation(
        self, installation_id: int, account_login: str, tenant_id: str = "default"
    ) -> None:
        with self._lock, self._connect() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO installations"
                "(installation_id,account_login,created_at,tenant_id) VALUES (?, ?, ?, ?)",
                (installation_id, account_login, utc_now(), tenant_id),
            )

    def installation_tenant(self, installation_id: int) -> Optional[str]:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT tenant_id FROM installations WHERE installation_id=?", (installation_id,)
            ).fetchone()
        return str(row["tenant_id"]) if row else None

    def save_checkpoint(
        self, task_id: str, node: str, state: Dict[str, Any], status: str = "completed",
        attempt: int = 1, error: str = "",
    ) -> None:
        with self._lock, self._connect() as conn:
            conn.execute(
                "INSERT INTO checkpoints(task_id,node,status,attempt,state_json,error,updated_at) "
                "VALUES (?,?,?,?,?,?,?) ON CONFLICT(task_id,node) DO UPDATE SET "
                "status=excluded.status,attempt=excluded.attempt,state_json=excluded.state_json,"
                "error=excluded.error,updated_at=excluded.updated_at",
                (task_id, node, status, attempt, json.dumps(state, ensure_ascii=False),
                 error[:2000] or None, utc_now()),
            )

    def load_checkpoints(self, task_id: str) -> Dict[str, Dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT node,status,attempt,state_json,error,updated_at FROM checkpoints "
                "WHERE task_id=? ORDER BY updated_at", (task_id,)
            ).fetchall()
        result = {}
        for row in rows:
            item = dict(row)
            item["state"] = json.loads(item.pop("state_json"))
            result[item.pop("node")] = item
        return result

    def save_task_payload(self, task_id: str, diff: str) -> None:
        with self._lock, self._connect() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO task_payloads(task_id,diff,created_at) VALUES (?,?,?)",
                (task_id, diff, utc_now()),
            )

    def update_task_input(self, task_id: str, updates: Dict[str, Any]) -> None:
        with self._lock, self._connect() as conn:
            row = conn.execute(
                "SELECT input_json FROM tasks WHERE id=?", (task_id,)
            ).fetchone()
            if not row:
                raise ValueError("task not found")
            value = json.loads(row["input_json"])
            value.update(updates)
            conn.execute(
                "UPDATE tasks SET input_json=?,updated_at=? WHERE id=?",
                (json.dumps(value, ensure_ascii=False), utc_now(), task_id),
            )

    def get_task_payload(self, task_id: str) -> Optional[str]:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT diff FROM task_payloads WHERE task_id=?", (task_id,)
            ).fetchone()
        return str(row["diff"]) if row else None

    def request_cancel(self, task_id: str, tenant_id: Optional[str] = None) -> bool:
        query = "UPDATE tasks SET cancel_requested=1,updated_at=? WHERE id=?"
        params = [utc_now(), task_id]
        if tenant_id is not None:
            query += " AND tenant_id=?"
            params.append(tenant_id)
        with self._lock, self._connect() as conn:
            cursor = conn.execute(query, params)
            return cursor.rowcount > 0

    def is_cancelled(self, task_id: str) -> bool:
        with self._connect() as conn:
            row = conn.execute("SELECT cancel_requested FROM tasks WHERE id=?", (task_id,)).fetchone()
        return bool(row and row["cancel_requested"])

    def cancel(self, task_id: str, event: TraceEvent) -> None:
        with self._lock, self._connect() as conn:
            conn.execute(
                "UPDATE tasks SET state=?,updated_at=? WHERE id=?",
                (TaskState.CANCELLED.value, event.created_at, task_id),
            )
            conn.execute(
                "INSERT INTO trace_events(task_id,step,state,message,created_at) VALUES (?,?,?,?,?)",
                (task_id, event.step, event.state.value, event.message, event.created_at),
            )

    def claim_webhook(
        self, delivery_id: str, tenant_id: str, event_type: str, payload_sha256: str,
    ) -> bool:
        if not delivery_id:
            raise ValueError("X-GitHub-Delivery is required")
        with self._lock, self._connect() as conn:
            try:
                conn.execute(
                    "INSERT INTO webhook_deliveries"
                    "(delivery_id,tenant_id,event_type,payload_sha256,received_at) VALUES (?,?,?,?,?)",
                    (delivery_id, tenant_id, event_type, payload_sha256, utc_now()),
                )
                return True
            except sqlite3.IntegrityError:
                row = conn.execute(
                    "SELECT payload_sha256 FROM webhook_deliveries WHERE delivery_id=?",
                    (delivery_id,),
                ).fetchone()
                if row and row["payload_sha256"] != payload_sha256:
                    raise ValueError("delivery id was already used with a different payload")
                return False

    def complete_webhook(self, delivery_id: str, task_id: Optional[str]) -> None:
        with self._lock, self._connect() as conn:
            conn.execute(
                "UPDATE webhook_deliveries SET task_id=? WHERE delivery_id=?",
                (task_id, delivery_id),
            )

    def get_webhook(self, delivery_id: str) -> Optional[Dict[str, Any]]:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM webhook_deliveries WHERE delivery_id=?", (delivery_id,)
            ).fetchone()
        return dict(row) if row else None

    def create_user(
        self, user_id: str, username: str, password_hash: str,
        tenant_id: str, role: str,
    ) -> None:
        with self._lock, self._connect() as conn:
            conn.execute(
                "INSERT OR IGNORE INTO users(id,username,password_hash,created_at) VALUES (?,?,?,?)",
                (user_id, username, password_hash, utc_now()),
            )
            row = conn.execute("SELECT id FROM users WHERE username=?", (username,)).fetchone()
            conn.execute(
                "INSERT INTO memberships(user_id,tenant_id,role) VALUES (?,?,?) "
                "ON CONFLICT(user_id,tenant_id) DO UPDATE SET role=excluded.role",
                (row["id"], tenant_id, role),
            )

    def get_user(self, username: str) -> Optional[Dict[str, Any]]:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT id,username,password_hash,active FROM users WHERE username=?", (username,)
            ).fetchone()
            if not row:
                return None
            memberships = conn.execute(
                "SELECT tenant_id,role FROM memberships WHERE user_id=?", (row["id"],)
            ).fetchall()
        value = dict(row)
        value["memberships"] = [dict(item) for item in memberships]
        return value

    def grant_repository(self, tenant_id: str, repository: str, auto_fix: bool = False) -> None:
        with self._lock, self._connect() as conn:
            conn.execute(
                "INSERT INTO repository_grants(tenant_id,repository,auto_fix) VALUES (?,?,?) "
                "ON CONFLICT(tenant_id,repository) DO UPDATE SET auto_fix=excluded.auto_fix",
                (tenant_id, repository, int(auto_fix)),
            )

    def repository_allowed(
        self, tenant_id: str, repository: str, require_auto_fix: bool = False,
    ) -> bool:
        with self._connect() as conn:
            total = conn.execute(
                "SELECT COUNT(*) AS n FROM repository_grants WHERE tenant_id=?", (tenant_id,)
            ).fetchone()["n"]
            row = conn.execute(
                "SELECT auto_fix FROM repository_grants WHERE tenant_id=? AND repository=?",
                (tenant_id, repository),
            ).fetchone()
        if total == 0:
            return True
        return bool(row and (not require_auto_fix or row["auto_fix"]))

    def audit(
        self, tenant_id: str, actor: str, action: str, resource: str,
        detail: Optional[Dict[str, Any]] = None,
    ) -> None:
        with self._lock, self._connect() as conn:
            conn.execute(
                "INSERT INTO audit_log(tenant_id,actor,action,resource,detail_json,created_at) "
                "VALUES (?,?,?,?,?,?)",
                (tenant_id, actor, action, resource,
                 json.dumps(detail or {}, ensure_ascii=False), utc_now()),
            )

    def list_audit(self, tenant_id: str, limit: int = 100) -> list:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT actor,action,resource,detail_json,created_at FROM audit_log "
                "WHERE tenant_id=? ORDER BY id DESC LIMIT ?",
                (tenant_id, max(1, min(limit, 500))),
            ).fetchall()
        values = []
        for row in rows:
            item = dict(row)
            item["detail"] = json.loads(item.pop("detail_json"))
            values.append(item)
        return values

    def save_deployment(self, tenant_id: str, skill_name: str, config: Dict[str, Any]) -> None:
        with self._lock, self._connect() as conn:
            conn.execute(
                "INSERT INTO deployments(tenant_id,skill_name,stable_version,candidate_version,"
                "canary_percent,shadow_percent,max_error_rate,min_samples,status,samples,errors,updated_at) "
                "VALUES (?,?,?,?,?,?,?,?,?,0,0,?) ON CONFLICT(tenant_id,skill_name) DO UPDATE SET "
                "stable_version=excluded.stable_version,candidate_version=excluded.candidate_version,"
                "canary_percent=excluded.canary_percent,shadow_percent=excluded.shadow_percent,"
                "max_error_rate=excluded.max_error_rate,min_samples=excluded.min_samples,"
                "status=excluded.status,samples=0,errors=0,updated_at=excluded.updated_at",
                (tenant_id, skill_name, config.get("stable_version"), config.get("candidate_version"),
                 int(config.get("canary_percent", 0)), int(config.get("shadow_percent", 0)),
                 float(config.get("max_error_rate", .1)), int(config.get("min_samples", 20)),
                 config.get("status", "running"), utc_now()),
            )
            conn.execute(
                "UPDATE deployments SET max_disagreement_rate=?,auto_promote=?,"
                "shadow_samples=0,disagreements=0 WHERE tenant_id=? AND skill_name=?",
                (float(config.get("max_disagreement_rate", .2)),
                 int(bool(config.get("auto_promote", False))), tenant_id, skill_name),
            )

    def get_deployment(self, tenant_id: str, skill_name: str) -> Optional[Dict[str, Any]]:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM deployments WHERE tenant_id=? AND skill_name=?",
                (tenant_id, skill_name),
            ).fetchone()
        return dict(row) if row else None

    def record_deployment_result(
        self, tenant_id: str, skill_name: str, failed: bool,
    ) -> Optional[Dict[str, Any]]:
        with self._lock, self._connect() as conn:
            conn.execute(
                "UPDATE deployments SET samples=samples+1,errors=errors+?,updated_at=? "
                "WHERE tenant_id=? AND skill_name=?",
                (int(failed), utc_now(), tenant_id, skill_name),
            )
            row = conn.execute(
                "SELECT * FROM deployments WHERE tenant_id=? AND skill_name=?",
                (tenant_id, skill_name),
            ).fetchone()
            if not row:
                return None
            value = dict(row)
            if (
                value["status"] == "running"
                and value["samples"] >= value["min_samples"]
                and value["errors"] / value["samples"] > value["max_error_rate"]
            ):
                conn.execute(
                    "UPDATE deployments SET status='rolled_back',canary_percent=0,"
                    "shadow_percent=0,updated_at=? WHERE tenant_id=? AND skill_name=?",
                    (utc_now(), tenant_id, skill_name),
                )
                value["status"] = "rolled_back"
        return value

    def record_shadow_observation(
        self, tenant_id: str, skill_name: str, task_id: str, lane: str,
        primary: Dict[str, Any], candidate: Optional[Dict[str, Any]],
        disagreement: float, candidate_failed: bool = False,
        candidate_only: int = 0, primary_only: int = 0,
    ) -> Optional[Dict[str, Any]]:
        with self._lock, self._connect() as conn:
            # candidate_version 从 deployments 现场读，不由调用方传入：调用方
            # 传的话，一次参数错误就会把观测记到别的候选名下，而这正是这一列
            # 要防的事。读不到部署时留 NULL（无法归属的证据不计入晋升）。
            current = conn.execute(
                "SELECT candidate_version FROM deployments WHERE tenant_id=? AND skill_name=?",
                (tenant_id, skill_name),
            ).fetchone()
            conn.execute(
                "INSERT INTO release_observations(tenant_id,skill_name,task_id,lane,"
                "primary_json,candidate_json,disagreement,candidate_failed,created_at,"
                "candidate_version,candidate_only,primary_only) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                (tenant_id, skill_name, task_id, lane,
                 json.dumps(primary, ensure_ascii=False),
                 json.dumps(candidate, ensure_ascii=False) if candidate is not None else None,
                 float(disagreement), int(candidate_failed), utc_now(),
                 current["candidate_version"] if current else None,
                 int(candidate_only), int(primary_only)),
            )
            conn.execute(
                "UPDATE deployments SET shadow_samples=shadow_samples+1,"
                "disagreements=disagreements+?,updated_at=? "
                "WHERE tenant_id=? AND skill_name=?",
                (int(disagreement > 0), utc_now(), tenant_id, skill_name),
            )
            row = conn.execute(
                "SELECT * FROM deployments WHERE tenant_id=? AND skill_name=?",
                (tenant_id, skill_name),
            ).fetchone()
            if not row:
                return None
            value = dict(row)
            disagreement_rate = (
                value["disagreements"] / value["shadow_samples"]
                if value["shadow_samples"] else 0.0
            )
            error_rate = value["errors"] / value["samples"] if value["samples"] else 0.0
            if (
                value["status"] == "running" and value["auto_promote"]
                and value["shadow_samples"] >= value["min_samples"]
                and disagreement_rate <= value["max_disagreement_rate"]
                and error_rate <= value["max_error_rate"]
                and not candidate_failed
            ):
                conn.execute(
                    "UPDATE deployments SET status='promoted',stable_version=candidate_version,"
                    "canary_percent=0,shadow_percent=0,updated_at=? "
                    "WHERE tenant_id=? AND skill_name=?",
                    (utc_now(), tenant_id, skill_name),
                )
                value["status"] = "promoted"
                candidate_version = value.get("candidate_version")
                # Keep skill_versions.active in sync with the deployment that is now
                # actually serving traffic, so evolution.py's next baseline read
                # (get_active_skill_version) does not diverge from production.
                # Inlined (not a call to activate_skill_version) because self._lock
                # is non-reentrant and is already held in this transaction.
                if candidate_version is not None and conn.execute(
                    "SELECT 1 FROM skill_versions WHERE skill_name = ? AND version = ?",
                    (skill_name, candidate_version),
                ).fetchone():
                    conn.execute(
                        "UPDATE skill_versions SET active = 0 WHERE skill_name = ?", (skill_name,)
                    )
                    conn.execute(
                        "UPDATE skill_versions SET active = 1 WHERE skill_name = ? AND version = ?",
                        (skill_name, candidate_version),
                    )
        return value

    def promote_deployment(
        self, tenant_id: str, skill_name: str, candidate_version: int,
    ) -> Optional[Dict[str, Any]]:
        """把候选晋升为 stable，并同步 `skill_versions.active`。

        用增量 UPDATE 而不是 `save_deployment`：后者会把
        `samples/errors/shadow_samples/disagreements` 全部清零，晋升时清零
        等于把刚刚用来做决定的那批证据擦掉，事后无法复核这次晋升凭什么发生。

        `candidate_version` 必须与部署当前的候选一致才写——判决与写回之间
        若有人换了候选，就会把 A 的证据用到 B 的晋升上。不一致时返回 None，
        由调用方重新判决。
        """
        with self._lock, self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM deployments WHERE tenant_id=? AND skill_name=?",
                (tenant_id, skill_name),
            ).fetchone()
            if not row:
                return None
            value = dict(row)
            if value["status"] != "running":
                return None
            if int(value["candidate_version"] or 0) != int(candidate_version):
                return None
            conn.execute(
                "UPDATE deployments SET status='promoted',stable_version=candidate_version,"
                "canary_percent=0,shadow_percent=0,updated_at=? "
                "WHERE tenant_id=? AND skill_name=?",
                (utc_now(), tenant_id, skill_name),
            )
            # 与生产实际服务的版本保持一致，否则 evolution.py 下一次读
            # get_active_skill_version 拿到的基线与线上不是同一个东西。
            # 内联而不是调用 activate_skill_version：self._lock 不可重入，
            # 这里已经持有它了（与下方 auto_promote 分支同一原因）。
            if conn.execute(
                "SELECT 1 FROM skill_versions WHERE skill_name = ? AND version = ?",
                (skill_name, int(candidate_version)),
            ).fetchone():
                conn.execute(
                    "UPDATE skill_versions SET active = 0 WHERE skill_name = ?", (skill_name,)
                )
                conn.execute(
                    "UPDATE skill_versions SET active = 1 WHERE skill_name = ? AND version = ?",
                    (skill_name, int(candidate_version)),
                )
            updated = conn.execute(
                "SELECT * FROM deployments WHERE tenant_id=? AND skill_name=?",
                (tenant_id, skill_name),
            ).fetchone()
        return dict(updated) if updated else None

    def summarise_shadow_evidence(
        self, tenant_id: str, skill_name: str, candidate_version: int,
    ) -> Dict[str, Any]:
        """汇总**属于指定候选版本**的影子观测。

        为什么按 candidate_version 过滤：`save_deployment` 只清零 deployments
        上的计数器，release_observations 的历史行会留下来。不过滤的话，上一个
        候选的观测会被算进这一个候选的晋升证据里，而报告上看不出来。

        `candidate_version IS NULL` 的旧行（这一列加入之前写的）**不计入**——
        无法归属的证据不能当成任何候选的证据。这会让老库的证据数看起来变少，
        那是正确的：那些行本来就不知道属于谁。

        计数口径：
        - `candidate_only_total` / `primary_only_total` 是分歧的两个方向，
          不能合成一个数（见 observe_shadow）；
        - `candidate_wins` = 至少有一条候选独有发现的观测数；
        - `candidate_losses` = 至少漏掉一条基线发现的观测数。
        """
        with self._connect() as conn:
            row = conn.execute(
                "SELECT COUNT(*) AS samples,"
                "SUM(candidate_failed) AS failures,"
                "SUM(CASE WHEN disagreement > 0 THEN 1 ELSE 0 END) AS disagreements,"
                "SUM(candidate_only) AS candidate_only_total,"
                "SUM(primary_only) AS primary_only_total,"
                "SUM(CASE WHEN candidate_only > 0 THEN 1 ELSE 0 END) AS candidate_wins,"
                "SUM(CASE WHEN primary_only > 0 THEN 1 ELSE 0 END) AS candidate_losses "
                "FROM release_observations "
                "WHERE tenant_id=? AND skill_name=? AND candidate_version=?",
                (tenant_id, skill_name, int(candidate_version)),
            ).fetchone()
        samples = int((row["samples"] if row else 0) or 0)
        return {
            "candidate_version": int(candidate_version),
            "samples": samples,
            "failures": int((row["failures"] if row else 0) or 0),
            "disagreements": int((row["disagreements"] if row else 0) or 0),
            "candidate_only_total": int((row["candidate_only_total"] if row else 0) or 0),
            "primary_only_total": int((row["primary_only_total"] if row else 0) or 0),
            "candidate_wins": int((row["candidate_wins"] if row else 0) or 0),
            "candidate_losses": int((row["candidate_losses"] if row else 0) or 0),
            # 分母为 0 时是 None，不是 0.0。0.0 会直接满足"≤ 阈值"，把
            # "一个样本都没有"伪装成"测过了，很干净"。
            "disagreement_rate": (
                int((row["disagreements"] if row else 0) or 0) / samples
                if samples else None
            ),
            # 退化率：只数"候选漏掉了基线报过的发现"这个方向。
            # 对称分歧率不能当否决条件——一个每次都多报一条真问题的候选，
            # 对称分歧率是 1.0，会被一道"分歧率 ≤ 阈值"的门禁当成退化拦下。
            # 风险在漏，不在多，所以门禁看这个数，对称分歧率只作展示。
            "loss_rate": (
                int((row["candidate_losses"] if row else 0) or 0) / samples
                if samples else None
            ),
            "failure_rate": (
                int((row["failures"] if row else 0) or 0) / samples
                if samples else None
            ),
        }

    def list_release_observations(
        self, tenant_id: str, skill_name: str, limit: int = 100,
    ) -> list:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM release_observations WHERE tenant_id=? AND skill_name=? "
                "ORDER BY id DESC LIMIT ?",
                (tenant_id, skill_name, max(1, min(limit, 500))),
            ).fetchall()
        values = []
        for row in rows:
            item = dict(row)
            item["primary"] = json.loads(item.pop("primary_json"))
            raw = item.pop("candidate_json")
            item["candidate"] = json.loads(raw) if raw else None
            values.append(item)
        return values

    def create_alert(
        self, tenant_id: str, alert_key: str, severity: str, message: str,
    ) -> None:
        now = utc_now()
        with self._lock, self._connect() as conn:
            conn.execute(
                "INSERT OR IGNORE INTO alerts"
                "(tenant_id,alert_key,severity,message,status,created_at,updated_at) "
                "VALUES (?,?,?,?, 'open',?,?)",
                (tenant_id, alert_key, severity, message[:1000], now, now),
            )

    def list_alerts(self, tenant_id: str, limit: int = 100) -> list:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM alerts WHERE tenant_id=? ORDER BY id DESC LIMIT ?",
                (tenant_id, max(1, min(limit, 500))),
            ).fetchall()
        return [dict(row) for row in rows]

    def dashboard_stats(self, tenant_id: Optional[str] = None) -> Dict[str, Any]:
        with self._connect() as conn:
            clause = " WHERE tenant_id=?" if tenant_id is not None else ""
            params = (tenant_id,) if tenant_id is not None else ()
            total = conn.execute("SELECT COUNT(*) AS n FROM tasks" + clause, params).fetchone()["n"]
            state_prefix = clause + (" AND " if clause else " WHERE ")
            success = conn.execute(
                "SELECT COUNT(*) AS n FROM tasks" + state_prefix + "state='SUCCESS'", params
            ).fetchone()["n"]
            failed = conn.execute(
                "SELECT COUNT(*) AS n FROM tasks" + state_prefix + "state='FAILED'", params
            ).fetchone()["n"]
            if tenant_id is None:
                failures = conn.execute(
                    "SELECT COUNT(*) AS n FROM failure_cases WHERE resolved=0"
                ).fetchone()["n"]
            else:
                failures = conn.execute(
                    "SELECT COUNT(*) AS n FROM failure_cases f JOIN tasks t ON t.id=f.task_id "
                    "WHERE f.resolved=0 AND t.tenant_id=?", (tenant_id,)
                ).fetchone()["n"]
            active_skills = conn.execute(
                "SELECT COUNT(*) AS n FROM skill_versions WHERE active = 1"
            ).fetchone()["n"]
            if tenant_id is None:
                active_skills += conn.execute(
                    "SELECT COUNT(*) AS n FROM skill_artifact_versions WHERE active=1"
                ).fetchone()["n"]
            else:
                active_skills += conn.execute(
                    "SELECT COUNT(*) AS n FROM skill_artifact_versions "
                    "WHERE tenant_id=? AND active=1", (tenant_id,)
                ).fetchone()["n"]
        return {
            "tasks_total": total, "tasks_success": success, "tasks_failed": failed,
            "success_rate": round(success / total, 4) if total else 0.0,
            "unresolved_failure_cases": failures, "active_skill_versions": active_skills,
        }


def create_store(database_url: str, sqlite_path: str) -> "TaskStore":
    """存储后端工厂。

    原来这里还有一个 PostgresTaskStore（939 行，与 TaskStore 平行实现
    62 个方法）。删掉了，理由是**它从没被执行过**：psycopg 不是安装依赖，
    没有一个测试覆盖它，EVOAGENT_DATABASE_URL 默认为空。

    权衡过三条路：
      1. 留着 —— 仓库多 939 行不能声称可用的代码。简历上写"支持
         PostgreSQL"就是在讲一个没验证过的功能，面试里一问就穿。
      2. 补测试补驱动 —— 要引真实 Postgres 才算真测过，投入远大于
         这个项目的收益，而且它不在评测链路上。
      3. 删掉，配了 Postgres URL 时**显式报错** —— 选这条。

    选 3 的关键是不能静默降级到 SQLite：那样配了 Postgres 的人会以为
    数据写进了 Postgres，实际写在本地文件里，出问题时排查方向全错。
    报错难看但诚实。
    """
    if database_url.startswith(("postgres://", "postgresql://")):
        raise NotImplementedError(
            "PostgreSQL backend was removed: it had no test coverage and no "
            "installed driver. Unset EVOAGENT_DATABASE_URL to use SQLite."
        )
    return TaskStore(sqlite_path)
