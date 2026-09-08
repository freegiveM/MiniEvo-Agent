# 项目状态与能力清单

下面按**证据等级**分组，而不是按功能分组。理由和 `prototypes/__init__.py`
里写的是同一条：一份能力清单里最容易骗人的地方，不是某一句话假，而是
**"跑过评测的"和"只写完了的"混在一起列**，读者没法区分。

### 一、在评测链路上，有量化结论

跑的是 `evaluation_v2.py` → `agentic_core.ModeRouterReviewer`，指标见
`docs/` 下的评测报告：

- 审查统一 diff，输出结构化问题、修复建议与测试建议
- 三种如实披露的运行模式：`rules-only`、`hybrid`、`agentic`
- Agentic 模式四个 LLM 角色：Planner、Security、Correctness/Reliability、Critic
- 有界 Agent Loop：Tool Registry、参数 Schema 校验、结构化 Observation，
  以及 token/时间/步数三重预算（超预算记 `budget_exhausted` 后中止）
- 按 task graph 给 specialist 分派文件范围，**在工具层**拒绝越界读取并记账
- 证据门禁：把"缺哪类证据"回灌给 critic，与门禁判决保持两道独立过滤
- 失败案例回流、提示词评测、版本激活与回滚
- SQLite 保存任务状态、执行轨迹与最终报告

修复闭环（LLM unified patch、AST/CST、隔离工作副本内的前后测试对比、
只开 Draft PR）也在这条链路上，但**基准集里 8 条修复只有 1 条标了
`auto_fixable`，所以这一段实际被跑到的次数很少**，不算量过。

真实 PR 数据集（`datasets/real-pr-v1.jsonl` 95 条正样本 +
`datasets/real-pr-clean-v1.jsonl` 78 条负样本）上的 D6 全量 replay 结果见
`output/real-pr-regression/d6-replay.json`，口径与局限见
`datasets/README.md` 第八、九节。三条必须一起读的限定：

- **假阳性率第一次在真实数据上可测**：`clean_accuracy = 0.7308`。此前真实
  数据集里 `clean_total` 恒为 0，这一档从未跑过。负样本的"无缺陷"是
  冷却期代理信号，不是证明。
- **区间比点估计更重要**：`high_severity_recall = 0.2778`，但 95% Wilson
  区间是 [0.125, 0.509]——分母只有 18，这个规模下说不出"提升了多少"。
  `precision` [0.685, 0.836] 和 `recall` [0.469, 0.620] 分母在 78-117，
  可以做粗粒度比较。
- **severity 标签本身还不可信**：它来自 `dataset_builder` 的八类正则查表
  （类别 → 固定 severity），`classify_defect_with_basis` 自己记录过 63.2%
  是 fallback。LLM-as-judge 重标已跑完全量 165 条
  （`output/severity-relabel/relabel-v1.json`，口径见
  `docs/severity-rubric.md`）：一致率 0.4061、**κ = −0.0019**，两套标注
  统计独立。这足以证伪原标签，**不足以充当新真值**——κ≈0 区分不了
  "judge 对、正则是噪声"和"两边都是噪声"。人工校准抽样已就位
  （`scripts/sample_severity_calibration.py`，31 条待判），未通过
  κ≥0.6 且一致率≥0.85 的门禁前不得当 ground truth。另注：新标签下
  `high_or_above` 分母 18 → 44，与旧标签下的 `high_severity_recall`
  **不是同一个量**，不可放进同一张趋势图。

### 二、实现完整、有单测，但不在评测链路上

这些代码只经过 `service.py`，`agentic_core` 里一次都没出现过，
所以简历上不能拿它们当"验证过的设计"：

- 覆盖任务/工具/反馈/记忆/观察/Diff 的统一 Context Window 与逐轮压缩
  （`context_manager.py`；评测链路走的是 `BoundedRole` 的硬预算截断，不压缩）
- Working/Episodic/Semantic 分层记忆、租户级检索、任务归档与过期清理
- GitHub `pull_request` webhook、HMAC-SHA256 签名校验、PR 评论回写
- Webhook delivery 幂等、重放时间窗与评论 upsert
- PR 合并推断反馈（`merged_without_addressing`，默认关闭）：**只有记录路径跑过测试，
  没有一条真实 PR 的推断信号**。它刻意不进提示词进化，所以即便开启也不会改变
  第一节里的任何数字——它的作用是让"拒绝"这条路径有真实输入，不是提升分数
- 闭环流转基建（消费账本、根因指纹与频率分流、候选生成阶段的记忆召回与
  GEPA 式反思信号、DGM/GEPA 式版本档案与逐样本 Pareto 选亲、影子放量
  接线、影子晋升判决、反馈入口、已验证规则保留清点）：修掉了三处真实的
  断流（LLM 路径永不 `activated` → 反馈永不消费 → 第二轮起固定返回
  "没有新信号"；`shadow_ready` 无人消费 → 候选出不来；影子证据攒够之后
  没有基于证据的判决 → 候选上得去下不来），并按 ACE 的 context collapse
  失效模式审计出第四个问题：整体重写式生成 + 只校验通用 token 的
  completeness 门禁保护不了逐代积累的已验证规则（已用刻画测试钉住缺口，
  清点函数已实现并接进 `_propose` 的 `gates`——**纯报告项，不进
  `decision`**；delta 合并层也已接进 `auto_propose` 的候选生成路径）。
  反馈入口从 D6 回放派生出 **194 条待人工确认的候选**，并已产出一份
  确定性抽样（30 条）的人工确认清单
  （`output/feedback-labelling/worksheet-expected.md`）；**标注本身仍未做**，
  因此 `failure_cases` 里目前仍是 **0 条真实线上反馈**——自动对出来的差集
  不算反馈，理由见下文第 7 项。
  证据强度是"单测证明链路不会再卡住"，不是"在真实反馈流上验证过"。
  选亲默认 `active`，即默认行为与这套档案加入之前完全一致——`pareto`
  在当前区间宽度（0.15–0.17）下大概率只是在噪声里随机游走
- **拒绝路径已在端到端回放里打响过**（`output/rejection-proof/`，见下文
  「拒绝路径证明」）。此前 `output/` 下全部历史报告的 `decision` 只有
  `activated` 一个值，holdout 门禁——这套系统唯一的抗过拟合检查——从未
  真的拦下过任何东西。现在有一个可复现的过拟合候选：验证集满分且受保护
  指标零退化，仅 `holdout_non_regression` 一道门禁拦下。语料仍是
  `synthetic-controlled`
- 用户登录、RBAC、租户/仓库隔离与不可变管理审计
- 动态 Skill 加载：manifest 必填 sha256 校验 + 可选 HMAC 签名 + AST import 白名单
- 自研 Agent Runtime、持久化 checkpoint 与任务断点续跑
- 灰度发布与影子流量、Web 管理台、任务 Dashboard
- OpenTelemetry Trace、Prometheus 指标与持久化告警
- JSON API 与 Markdown 报告

### 三、写了但这台机器上跑不到

留在仓库里是因为它们是降级路径的另一半，但**必须标注**：

- Redis Streams ACK、Worker 租约、指数退避重试、死信队列
  （`task_queue.py`；本机没装 `redis`，配了 URL 会直接报错而不是静默降级，
  测试覆盖的是内存 ACK 后端）
- Skill 的 Docker 隔离（`--network none`）；不配镜像时退化为
  audit hook 子进程（拦 socket/subprocess/os.system 与越界 open），
  且 `RLIMIT_AS`/`RLIMIT_CPU` **仅在 POSIX 生效**，Windows 上没有内存上限
- PostgreSQL 后端已删除：无驱动、无测试，配了 URL 现在抛
  `NotImplementedError`（见 `store.create_store`）

