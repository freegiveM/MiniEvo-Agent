import os
import re
from dataclasses import dataclass
from typing import Dict, Iterable, Optional


_DOTENV_KEY = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


def load_dotenv(paths: Optional[Iterable[str]] = None) -> None:
    """Load local dotenv files without overriding real process environment values.

    The project-root file has priority over ``evoagent/.env``.  This allows the
    latter to remain compatible with existing local setups while keeping the
    conventional root-level ``.env`` as the recommended location.
    """
    package_dir = os.path.dirname(os.path.abspath(__file__))
    project_root = os.path.dirname(package_dir)
    candidates = list(paths) if paths is not None else [
        os.path.join(project_root, ".env"),
        os.path.join(package_dir, ".env"),
    ]
    for path in candidates:
        try:
            with open(path, "r", encoding="utf-8-sig") as handle:
                lines = handle.readlines()
        except OSError:
            continue
        for raw_line in lines:
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            if line.startswith("export "):
                line = line[7:].lstrip()
            if "=" not in line:
                continue
            key, value = (part.strip() for part in line.split("=", 1))
            if not _DOTENV_KEY.fullmatch(key):
                continue
            if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
                value = value[1:-1]
            os.environ.setdefault(key, value)


load_dotenv()


def _int(name: str, default: int) -> int:
    value = int(os.getenv(name, str(default)))
    if value <= 0:
        raise ValueError("%s must be positive" % name)
    return value


def _bool(name: str, default: bool = False) -> bool:
    return os.getenv(name, str(default)).strip().lower() in {"1", "true", "yes", "on"}


def _non_negative_int(name: str, default: int) -> int:
    value = int(os.getenv(name, str(default)))
    if value < 0:
        raise ValueError("%s must be non-negative" % name)
    return value


@dataclass(frozen=True)
class Settings:
    host: str
    port: int
    db_path: str
    max_diff_bytes: int
    max_steps: int
    timeout_seconds: int
    llm_base_url: str
    llm_api_key: str
    llm_model: str
    github_webhook_secret: str
    github_token: str
    auto_post_review: bool
    database_url: str = ""
    redis_url: str = ""
    async_workers: int = 2
    agent_max_workers: int = 4
    agent_retries: int = 1
    collaboration_rounds: int = 2
    agent_loop_max_steps: int = 4
    agent_loop_timeout_seconds: int = 45
    context_max_tokens: int = 12000
    context_reserved_tokens: int = 2500
    memory_enabled: bool = True
    memory_recall_limit: int = 6
    memory_working_ttl_seconds: int = 86400
    skills_dir: str = "skills"
    github_app_id: str = ""
    github_app_slug: str = ""
    github_private_key_path: str = ""
    public_base_url: str = "http://127.0.0.1:8080"
    llm_provider: str = "local"
    deepseek_api_key: str = ""
    openrouter_api_key: str = ""
    openrouter_site_url: str = ""
    openrouter_app_name: str = "EvoAgent"
    # PR 合并/关闭事件推断出的反馈。默认关闭：推断信号的置信度低于人工
    # 确认，静默开启会让一条"PR 合并了"被当成"人类确认这条报告是对的"。
    infer_feedback_from_merge: bool = False
    # 一个根因指纹要出现几次才够格触发候选生成 + 全量回放。低于这个数
    # 只写记忆，不发起那几十次 LLM 调用。
    #
    # 默认 1 = 行为与本改动之前一致（任何一条反馈都触发）。刻意不默认成
    # 3：那会静默改变现有部署的行为，让原本能触发的反馈突然不触发，而
    # 使用者没做过这个选择。真实失败频率分布要跑一段数据才知道，阈值该
    # 由观察决定，不由我猜。
    #
    # 轨道 F 的 val 晋升条件复用同一个值——"多次出现"在这个项目里只能
    # 有一个标准。
    evolution_root_cause_min_occurrences: int = 1
    # 同一个根因指纹最多被尝试几次。反复尝试反复失败说明"改提示词"对这
    # 类根因无效，不该无限重试烧钱。0 = 不限制。
    evolution_max_attempts_per_root_cause: int = 3
    # 单轮最多回传几条历史尝试当反思信号。
    #
    # 回传数不设上限时，账本会随轮次单调增长，而它整条塞进候选生成那一次
    # 调用的输入里。`evolution_generator_token_budget` 封的是**输出**
    # （max_tokens），封不住输入——所以后果不是报错，是反思信号把输入撑大，
    # 挤掉真正要看的 `failure_cases` 和 `active_prompt`，而且看不出来。
    #
    # 默认 12：`_prior_attempts` 原先硬编码在生成器里的上限是 20
    # （`evolution_v2.generate` 的 `[:20]`），那个数字没有依据且切在错误的
    # 层——生成器拿到什么由调用方决定，不该由生成器自己截。取 12 是因为
    # 同一基线上能积累的尝试数受 `max_attempts_per_root_cause` 约束，单轮
    # 根因数通常是个位数，12 条足够覆盖而不至于挤占预算。
    #
    # 排序在 `_prior_attempts` 里：先按"这个根因试过几次"降序（试得最多的
    # 最该被劝阻），再按时间倒序。截断时报出丢了几条，不静默切。
    evolution_max_reflection_attempts: int = 12
    # 下一轮从哪个提示词版本改起。"active" | "best" | "pareto" |
    # "epsilon_greedy"，见 evoagent/archive.py。
    #
    # 默认 "active" = 行为与档案选亲加入之前完全一致。刻意不默认成
    # "pareto"：当前 validation 区间宽度 0.15-0.17，"档案里哪个版本更好"
    # 这个判断本身噪声就比策略之间的差异大，激进选亲很可能只是在噪声里
    # 随机游走，却让人以为在做搜索。基建先就位，切策略等有数据支撑。
    evolution_parent_strategy: str = "active"
    # epsilon_greedy 的探索概率。仅该策略下生效。
    evolution_parent_epsilon: float = 0.1
    # 候选生成那一次 LLM 调用的 max_tokens。
    #
    # 默认从 6000 抬到 16000 再到 32000。两次抬高是同一个原因的两种表现：
    # **`max_tokens` 同时封顶 reasoning + content**，而推理占大头。
    #
    # 6000：全部花在推理上（`finish_reason=length`、`reasoning_tokens=6000`、
    # `content=''`），一条候选都产不出来。
    #
    # 16000：实测 25 条反馈下 `completion_tokens=13299`（其中推理 11740，
    # 内容只有 1559），只剩 17% 余量。推理多花几百个 token 就会把 content
    # 截在半截——表现为**间歇性失败**，同样的输入重放一次往往就过了。回路 C
    # 第一轮就是这么死的。而反馈条数还会继续涨（误报侧才 5 条），顶着上限
    # 跑等于让闭环随机失败。
    #
    # 抬高的代价是单轮成本上升，但**产不出候选的调用照常计费**——那次失败
    # 的调用付了 13299 token 的钱，什么都没换回来。截断的那种更糟：它可能
    # 恰好解析成功，于是一份缺了后半截的候选被当成完整的送进门禁。
    evolution_generator_token_budget: int = 32000
    # 每个切分单轮回放的样本上限。
    #
    # 默认从 5 抬到 20：**5 条下受保护指标的分母只有个位数,门禁量到的
    # 主要是噪声**。实测 validation 在 limit=5 时取出 3 缺陷 + 2 干净,于是
    # `severity_accuracy` 的分母是 2 或 3——一条样本就动 33 个点,
    # `clean_accuracy` 的步长是 0.5,Wilson 区间宽到几乎任何两个候选都
    # "不显著"。回路 B 第一轮那次 1.0 → 0.667 的"回退"就是这么来的。
    #
    # 20 是按分层取样的实际形状挑的:validation 10 缺陷 + 10 干净,
    # holdout 18 缺陷 + 2 干净,两个方向的分母都进入两位数。再往上抬收益
    # 递减而成本线性涨——单轮回放次数是 `4 × max_cases`(两个切分 ×
    # baseline/candidate),20 就是每轮 80 次 LLM 调用。
    #
    # 库存不是瓶颈(validation 23 缺陷 + 65 干净,holdout 110 + 16),这个
    # 数纯粹是预算取舍,所以留在环境变量里可调。
    eval_max_cases: int = 20
    eval_min_cases: int = 3
    eval_min_improvement: float = 0.01
    eval_min_holdout_cases: int = 2
    eval_max_metric_regression: float = 0.0
    auth_required: bool = False
    auth_secret: str = ""
    bootstrap_admin_username: str = ""
    bootstrap_admin_password: str = ""
    default_tenant_id: str = "default"
    session_ttl_seconds: int = 3600
    webhook_max_age_seconds: int = 600
    queue_max_attempts: int = 3
    queue_lease_seconds: int = 60
    skill_timeout_seconds: int = 30
    skill_memory_mb: int = 256
    skill_sandbox: bool = True
    skill_signing_key: str = ""
    skill_container_image: str = ""
    repair_test_command: str = ""
    repair_verify_timeout_seconds: int = 120
    otel_endpoint: str = ""
    otel_service_name: str = "evoagent"
    alert_failure_rate: float = 0.20
    alert_min_samples: int = 10
    alert_window_seconds: int = 900
    alert_webhook_url: str = ""
    alert_smtp_host: str = ""
    alert_email_to: str = ""
    continuous_eval_seconds: int = 0
    default_run_mode: str = ""
    agent_token_budget: int = 8000
    agent_time_budget_seconds: int = 60
    enabled_agents: str = "planner,security,correctness-reliability,critic"
    llm_input_cost_per_million: float = 0.0
    llm_output_cost_per_million: float = 0.0
    evaluation_min_public_prs: int = 300
    evaluation_min_f1_improvement: float = 0.03
    evaluation_min_high_risk_improvement: float = 0.05

    def resolved_llm(self) -> Dict[str, object]:
        """Resolve a named provider to the existing OpenAI-compatible transport."""
        provider = self.llm_provider.strip().lower()
        if provider in {"", "local", "none"}:
            if self.llm_base_url or self.llm_api_key or self.llm_model:
                provider = "custom"
            else:
                return {}

        if provider == "deepseek":
            api_key = self.deepseek_api_key or self.llm_api_key
            if not api_key:
                raise ValueError("DeepSeek requires EVOAGENT_DEEPSEEK_API_KEY")
            return {
                "provider": "deepseek",
                "base_url": self.llm_base_url or "https://api.deepseek.com",
                "api_key": api_key,
                "model": self.llm_model or "deepseek-v4-flash",
                "headers": {},
            }

        if provider in {"openrouter-deepseek-free", "openrouter_deepseek_free"}:
            api_key = self.openrouter_api_key or self.llm_api_key
            if not api_key:
                raise ValueError("OpenRouter requires EVOAGENT_OPENROUTER_API_KEY")
            headers = {}
            if self.openrouter_site_url:
                headers["HTTP-Referer"] = self.openrouter_site_url
            if self.openrouter_app_name:
                headers["X-Title"] = self.openrouter_app_name
            return {
                "provider": "openrouter-deepseek-free",
                "base_url": self.llm_base_url or "https://openrouter.ai/api/v1",
                "api_key": api_key,
                "model": self.llm_model or "deepseek/deepseek-chat-v3-0324:free",
                "headers": headers,
            }

        if provider == "openrouter-free":
            api_key = self.openrouter_api_key or self.llm_api_key
            if not api_key:
                raise ValueError("OpenRouter requires EVOAGENT_OPENROUTER_API_KEY")
            headers = {}
            if self.openrouter_site_url:
                headers["HTTP-Referer"] = self.openrouter_site_url
            if self.openrouter_app_name:
                headers["X-Title"] = self.openrouter_app_name
            return {
                "provider": "openrouter-free",
                "base_url": self.llm_base_url or "https://openrouter.ai/api/v1",
                "api_key": api_key,
                "model": self.llm_model or "openrouter/free",
                "headers": headers,
            }

        if provider == "custom":
            if not (self.llm_base_url and self.llm_api_key and self.llm_model):
                raise ValueError(
                    "Custom LLM requires EVOAGENT_LLM_BASE_URL, "
                    "EVOAGENT_LLM_API_KEY and EVOAGENT_LLM_MODEL"
                )
            return {
                "provider": "custom",
                "base_url": self.llm_base_url,
                "api_key": self.llm_api_key,
                "model": self.llm_model,
                "headers": {},
            }
        raise ValueError("unsupported EVOAGENT_LLM_PROVIDER: %s" % self.llm_provider)

    def validate_evolution(self) -> None:
        if self.eval_min_cases > self.eval_max_cases:
            raise ValueError("EVOAGENT_EVAL_MIN_CASES cannot exceed EVOAGENT_EVAL_MAX_CASES")
        if not 0.0 <= self.eval_min_improvement <= 1.0:
            raise ValueError("EVOAGENT_EVAL_MIN_IMPROVEMENT must be between 0 and 1")
        if self.eval_min_holdout_cases > self.eval_max_cases:
            raise ValueError("EVOAGENT_EVAL_MIN_HOLDOUT_CASES cannot exceed EVOAGENT_EVAL_MAX_CASES")
        if not 0.0 <= self.eval_max_metric_regression <= 1.0:
            raise ValueError("EVOAGENT_EVAL_MAX_METRIC_REGRESSION must be between 0 and 1")
        # 下限取 2000 而不是 1：推理模型上预算不足的表现是"content 空串 +
        # finish_reason=length"，一次调用照常计费却产不出候选。配一个装不下
        # 一次生成的预算，等于让回路静默停在这里——那与第 16.6 节那个假装在
        # 工作的门禁是同一种毛病。
        if self.evolution_generator_token_budget < 2000:
            raise ValueError(
                "EVOAGENT_EVOLUTION_GENERATOR_TOKEN_BUDGET must be at least 2000"
            )
        if self.auth_required and len(self.auth_secret.encode("utf-8")) < 32:
            raise ValueError(
                "EVOAGENT_AUTH_SECRET must contain at least 32 bytes when authentication is enabled"
            )
        if bool(self.bootstrap_admin_username) != bool(self.bootstrap_admin_password):
            raise ValueError("bootstrap admin username and password must be configured together")
        if not 0.0 <= self.alert_failure_rate <= 1.0:
            raise ValueError("EVOAGENT_ALERT_FAILURE_RATE must be between 0 and 1")
        if self.agent_max_workers < 1:
            raise ValueError("EVOAGENT_AGENT_MAX_WORKERS must be at least 1")
        if self.agent_retries < 0:
            raise ValueError("EVOAGENT_AGENT_RETRIES cannot be negative")
        if self.collaboration_rounds < 1:
            raise ValueError("EVOAGENT_COLLABORATION_ROUNDS must be at least 1")
        if self.agent_loop_max_steps < 1:
            raise ValueError("EVOAGENT_AGENT_LOOP_MAX_STEPS must be at least 1")
        if self.context_max_tokens < 512:
            raise ValueError("EVOAGENT_CONTEXT_MAX_TOKENS must be at least 512")
        if not 0 <= self.context_reserved_tokens < self.context_max_tokens:
            raise ValueError(
                "EVOAGENT_CONTEXT_RESERVED_TOKENS must be smaller than the context budget"
            )
        if self.default_run_mode not in {"", "rules-only", "hybrid", "agentic"}:
            raise ValueError("EVOAGENT_DEFAULT_RUN_MODE must be rules-only, hybrid or agentic")
        if self.llm_input_cost_per_million < 0 or self.llm_output_cost_per_million < 0:
            raise ValueError("LLM token prices cannot be negative")
        if self.evaluation_min_public_prs < 300:
            raise ValueError("EVOAGENT_EVALUATION_MIN_PUBLIC_PRS must be at least 300")

    @classmethod
    def from_env(cls) -> "Settings":
        return cls(
            host=os.getenv("EVOAGENT_HOST", "127.0.0.1"),
            port=_int("EVOAGENT_PORT", 8080),
            db_path=os.getenv("EVOAGENT_DB_PATH", "evoagent.db"),
            max_diff_bytes=_int("EVOAGENT_MAX_DIFF_BYTES", 1024 * 1024),
            max_steps=_int("EVOAGENT_MAX_STEPS", 8),
            timeout_seconds=_int("EVOAGENT_TIMEOUT_SECONDS", 120),
            llm_base_url=os.getenv("EVOAGENT_LLM_BASE_URL", "").rstrip("/"),
            llm_api_key=os.getenv("EVOAGENT_LLM_API_KEY", ""),
            llm_model=os.getenv("EVOAGENT_LLM_MODEL", ""),
            github_webhook_secret=os.getenv("EVOAGENT_GITHUB_WEBHOOK_SECRET", ""),
            github_token=os.getenv("EVOAGENT_GITHUB_TOKEN", ""),
            auto_post_review=_bool("EVOAGENT_AUTO_POST_REVIEW"),
            database_url=os.getenv("EVOAGENT_DATABASE_URL", ""),
            redis_url=os.getenv("EVOAGENT_REDIS_URL", ""),
            async_workers=_int("EVOAGENT_ASYNC_WORKERS", 2),
            agent_max_workers=_int("EVOAGENT_AGENT_MAX_WORKERS", 4),
            agent_retries=_non_negative_int("EVOAGENT_AGENT_RETRIES", 1),
            collaboration_rounds=_int("EVOAGENT_COLLABORATION_ROUNDS", 2),
            agent_loop_max_steps=_int("EVOAGENT_AGENT_LOOP_MAX_STEPS", 4),
            agent_loop_timeout_seconds=_int("EVOAGENT_AGENT_LOOP_TIMEOUT_SECONDS", 45),
            context_max_tokens=_int("EVOAGENT_CONTEXT_MAX_TOKENS", 12000),
            context_reserved_tokens=_non_negative_int(
                "EVOAGENT_CONTEXT_RESERVED_TOKENS", 2500
            ),
            memory_enabled=_bool("EVOAGENT_MEMORY_ENABLED", True),
            memory_recall_limit=_int("EVOAGENT_MEMORY_RECALL_LIMIT", 6),
            memory_working_ttl_seconds=_int(
                "EVOAGENT_MEMORY_WORKING_TTL_SECONDS", 86400
            ),
            skills_dir=os.getenv("EVOAGENT_SKILLS_DIR", "skills"),
            github_app_id=os.getenv("EVOAGENT_GITHUB_APP_ID", ""),
            github_app_slug=os.getenv("EVOAGENT_GITHUB_APP_SLUG", ""),
            github_private_key_path=os.getenv("EVOAGENT_GITHUB_PRIVATE_KEY_PATH", ""),
            public_base_url=os.getenv("EVOAGENT_PUBLIC_BASE_URL", "http://127.0.0.1:8080").rstrip("/"),
            llm_provider=os.getenv("EVOAGENT_LLM_PROVIDER", "local"),
            deepseek_api_key=os.getenv("EVOAGENT_DEEPSEEK_API_KEY", ""),
            openrouter_api_key=os.getenv("EVOAGENT_OPENROUTER_API_KEY", ""),
            openrouter_site_url=os.getenv("EVOAGENT_OPENROUTER_SITE_URL", ""),
            openrouter_app_name=os.getenv("EVOAGENT_OPENROUTER_APP_NAME", "EvoAgent"),
            infer_feedback_from_merge=_bool("EVOAGENT_INFER_FEEDBACK_FROM_MERGE", False),
            evolution_root_cause_min_occurrences=_int(
                "EVOAGENT_EVOLUTION_ROOT_CAUSE_MIN_OCCURRENCES", 1),
            evolution_max_attempts_per_root_cause=_non_negative_int(
                "EVOAGENT_EVOLUTION_MAX_ATTEMPTS_PER_ROOT_CAUSE", 3),
            evolution_max_reflection_attempts=_non_negative_int(
                "EVOAGENT_EVOLUTION_MAX_REFLECTION_ATTEMPTS", 12),
            evolution_parent_strategy=os.getenv(
                "EVOAGENT_EVOLUTION_PARENT_STRATEGY", "active").strip() or "active",
            evolution_parent_epsilon=float(
                os.getenv("EVOAGENT_EVOLUTION_PARENT_EPSILON", "0.1")),
            evolution_generator_token_budget=_int(
                "EVOAGENT_EVOLUTION_GENERATOR_TOKEN_BUDGET", 32000),
            eval_max_cases=_int("EVOAGENT_EVAL_MAX_CASES", 20),
            eval_min_cases=_int("EVOAGENT_EVAL_MIN_CASES", 3),
            eval_min_improvement=float(os.getenv("EVOAGENT_EVAL_MIN_IMPROVEMENT", "0.01")),
            eval_min_holdout_cases=_non_negative_int("EVOAGENT_EVAL_MIN_HOLDOUT_CASES", 2),
            eval_max_metric_regression=float(
                os.getenv("EVOAGENT_EVAL_MAX_METRIC_REGRESSION", "0")
            ),
            auth_required=_bool("EVOAGENT_AUTH_REQUIRED", False),
            auth_secret=os.getenv("EVOAGENT_AUTH_SECRET", ""),
            bootstrap_admin_username=os.getenv("EVOAGENT_BOOTSTRAP_ADMIN_USERNAME", ""),
            bootstrap_admin_password=os.getenv("EVOAGENT_BOOTSTRAP_ADMIN_PASSWORD", ""),
            default_tenant_id=os.getenv("EVOAGENT_DEFAULT_TENANT_ID", "default"),
            session_ttl_seconds=_int("EVOAGENT_SESSION_TTL_SECONDS", 3600),
            webhook_max_age_seconds=_int("EVOAGENT_WEBHOOK_MAX_AGE_SECONDS", 600),
            queue_max_attempts=_int("EVOAGENT_QUEUE_MAX_ATTEMPTS", 3),
            queue_lease_seconds=_int("EVOAGENT_QUEUE_LEASE_SECONDS", 60),
            skill_timeout_seconds=_int("EVOAGENT_SKILL_TIMEOUT_SECONDS", 30),
            skill_memory_mb=_int("EVOAGENT_SKILL_MEMORY_MB", 256),
            skill_sandbox=_bool("EVOAGENT_SKILL_SANDBOX", True),
            skill_signing_key=os.getenv("EVOAGENT_SKILL_SIGNING_KEY", ""),
            skill_container_image=os.getenv("EVOAGENT_SKILL_CONTAINER_IMAGE", ""),
            repair_test_command=os.getenv("EVOAGENT_REPAIR_TEST_COMMAND", ""),
            repair_verify_timeout_seconds=_int("EVOAGENT_REPAIR_VERIFY_TIMEOUT_SECONDS", 120),
            otel_endpoint=os.getenv("EVOAGENT_OTEL_ENDPOINT", ""),
            otel_service_name=os.getenv("EVOAGENT_OTEL_SERVICE_NAME", "evoagent"),
            alert_failure_rate=float(os.getenv("EVOAGENT_ALERT_FAILURE_RATE", "0.20")),
            alert_min_samples=_int("EVOAGENT_ALERT_MIN_SAMPLES", 10),
            alert_window_seconds=_int("EVOAGENT_ALERT_WINDOW_SECONDS", 900),
            alert_webhook_url=os.getenv("EVOAGENT_ALERT_WEBHOOK_URL", ""),
            alert_smtp_host=os.getenv("EVOAGENT_ALERT_SMTP_HOST", ""),
            alert_email_to=os.getenv("EVOAGENT_ALERT_EMAIL_TO", ""),
            continuous_eval_seconds=_non_negative_int(
                "EVOAGENT_CONTINUOUS_EVAL_SECONDS", 0
            ),
            default_run_mode=os.getenv("EVOAGENT_DEFAULT_RUN_MODE", "").strip().lower(),
            agent_token_budget=_int("EVOAGENT_AGENT_TOKEN_BUDGET", 8000),
            agent_time_budget_seconds=_int("EVOAGENT_AGENT_TIME_BUDGET_SECONDS", 60),
            enabled_agents=os.getenv(
                "EVOAGENT_ENABLED_AGENTS",
                "planner,security,correctness-reliability,critic",
            ),
            llm_input_cost_per_million=float(
                os.getenv("EVOAGENT_LLM_INPUT_COST_PER_MILLION", "0")
            ),
            llm_output_cost_per_million=float(
                os.getenv("EVOAGENT_LLM_OUTPUT_COST_PER_MILLION", "0")
            ),
            evaluation_min_public_prs=_int(
                "EVOAGENT_EVALUATION_MIN_PUBLIC_PRS", 300
            ),
            evaluation_min_f1_improvement=float(
                os.getenv("EVOAGENT_EVALUATION_MIN_F1_IMPROVEMENT", "0.03")
            ),
            evaluation_min_high_risk_improvement=float(
                os.getenv("EVOAGENT_EVALUATION_MIN_HIGH_RISK_IMPROVEMENT", "0.05")
            ),
        )
