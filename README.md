# EvoAgent PR Reviewer

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

## 快速开始

项目使用 Python 3.11。先安装锁定范围内的运行依赖，并在同一个 PowerShell 窗口中配置本地管理员：

```powershell
python -m pip install -r requirements.txt

$bytes = New-Object byte[] 32
[Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
$env:EVOAGENT_AUTH_REQUIRED = 'true'
$env:EVOAGENT_AUTH_SECRET = [Convert]::ToBase64String($bytes)
$env:EVOAGENT_BOOTSTRAP_ADMIN_USERNAME = 'admin'
$env:EVOAGENT_BOOTSTRAP_ADMIN_PASSWORD = '<替换为至少 10 个字符的密码>'

python -m evoagent
```

不要直接使用示例占位符作为密码或密钥。环境变量只对当前 PowerShell 及其子进程生效；修改配置后需要停止并重新启动 EvoAgent。

Bootstrap 管理员只在用户名尚不存在时创建；已有同名用户的密码不会在重启时被覆盖。

服务默认监听 `127.0.0.1:8080`。启动后打开 `http://127.0.0.1:8080/`，前端会在业务 API 返回未授权状态后显示登录层。登录状态保存在当前浏览器的 `localStorage` 中；需要重新登录时可以点击退出，或清除站点数据。

API 调用需要先登录并携带 Bearer Token：

```powershell
$session = Invoke-RestMethod -Method Post -Uri http://127.0.0.1:8080/v1/auth/login `
  -ContentType 'application/json' `
  -Body (@{username='admin'; password='<你的密码>'} | ConvertTo-Json)
$headers = @{Authorization="Bearer $($session.access_token)"}
Invoke-RestMethod -Method Post -Uri http://127.0.0.1:8080/v1/reviews `
  -Headers $headers `
  -ContentType 'application/json' `
  -Body (@{
    repository = 'demo/api'
    pull_request = 12
    mode = 'rules-only'
    diff = "diff --git a/app.py b/app.py`n--- a/app.py`n+++ b/app.py`n@@ -1 +1,2 @@`n+password = 'secret'`n+eval(user_input)"
  } | ConvertTo-Json)
```

查询任务：

```powershell
Invoke-RestMethod -Headers $headers http://127.0.0.1:8080/v1/tasks/<task-id>
Invoke-WebRequest -Headers $headers http://127.0.0.1:8080/v1/tasks/<task-id>/report
```

运行测试：

```powershell
python -m unittest discover -s tests -v
```

## 模型配置

每个请求可提交 `mode`：`rules-only`（纯扫描）、`hybrid`（扫描 + 单 LLM）或 `agentic`（Planner、Security、Correctness/Reliability、Critic 四个独立 LLM 角色）。后两者在没有模型配置时会明确降级到 `rules-only`。

每份 JSON/Markdown 报告包含实际模型调用数、工具调用数、输入/输出 Token、成本、延迟、失败调用和完整 Agent 轨迹。成本来自供应商响应的 `usage.cost` 或 `EVOAGENT_LLM_*_COST_PER_MILLION`；价格未配置时显示 0，不会猜测。若服务主机已有仓库 checkout，可在请求中传入绝对路径 `repository_root`，启用仓库全文、符号/调用关系、测试、配置/权限、AST、Git 历史和已安装静态分析器。

DeepSeek 官方 API（按 Token 计费）：

```powershell
$env:EVOAGENT_LLM_PROVIDER = 'deepseek'
$env:EVOAGENT_DEEPSEEK_API_KEY = '<deepseek-api-key>'
python -m evoagent
```

通过 OpenRouter 使用有速率限制、可用性可能变化的 DeepSeek 免费模型：

```powershell
$env:EVOAGENT_LLM_PROVIDER = 'openrouter-deepseek-free'
$env:EVOAGENT_OPENROUTER_API_KEY = '<openrouter-api-key>'
python -m evoagent
```

如果指定的免费 DeepSeek 版本下线，可将 `EVOAGENT_LLM_MODEL` 改为 OpenRouter 当前提供的其他 `:free` 模型，或把 Provider 改为 `openrouter-free` 让免费路由自动选择可用模型。

任意其他 OpenAI Chat Completions 兼容端点使用 `custom`：

```powershell
$env:EVOAGENT_LLM_PROVIDER = 'custom'
$env:EVOAGENT_LLM_BASE_URL = 'https://example.com/v1'
$env:EVOAGENT_LLM_API_KEY = '<token>'
$env:EVOAGENT_LLM_MODEL = '<model-name>'
```

密钥只通过环境变量读取，不要提交到仓库。

项目启动时会自动读取项目根目录的 `.env`，也兼容 `evoagent/.env`；系统环境变量优先于 `.env` 文件。推荐将以下内容写入根目录 `.env`（该文件已被 `.gitignore` 忽略）：

```env
EVOAGENT_LLM_PROVIDER=deepseek
EVOAGENT_DEEPSEEK_API_KEY=你的真实APIKey
```

## 评测与提示词进化

服务启动时会建立基础验证集和隐藏回归集。候选提示词不会接受调用方提供的“回归分数”作为上线依据，而是：

1. 使用当前提示词和候选提示词分别回放同一批验证 Diff；
2. 计算精确率、召回率、F1、严重级别正确率、高风险召回率、干净样本正确率和执行成功率；调用失败会按漏报或失败的干净样本计分；
3. 候选必须在验证集达到最小提升，并通过隐藏集的分数、精确率、召回率和高风险召回率非退化门禁；
4. 没有配置大模型，或验证集、隐藏集样本不足时只保存候选，状态为 `deferred`；
5. 评测记录包含提示词和数据集 SHA-256 指纹，隐藏集只持久化聚合指标，不暴露案例明细；
6. 没有新增有效反馈信号时不会重复创建内容相同的候选版本；
7. 所有评测运行、版本、指标和激活决定均持久化，可回滚。

可通过 `POST /v1/evaluation/cases` 增加版本化样本，`split` 支持 `train`、`validation` 和 `holdout`。样本名称和内容绑定且不可覆盖；修订样本必须使用新名称，重复提交相同内容则保持幂等。期望结果可选填 `rule_id`，用于避免“同一行但错误类别”的结果被算作命中。配置模型后，`POST /v1/evolution/auto` 会让模型聚类失败轨迹，生成结构化的 Prompt、few-shot、Planner 路由、工具策略与预算候选，再执行回放。通过门禁的候选状态为 `shadow_ready`；运行记录保存生成模型、失败案例、变更 diff、数据版本、成本和回滚点，且禁止候选修改生产 Python 代码。

仓库还提供可复现的受控离线进化证明：它只从 Validation 仓库的确认漏报中提取经过格式校验的 `rule_id`，自动生成 Prompt v2，然后在仓库完全隔离的 Holdout 上回放并保存真实版本链、`evolution_runs`、数据指纹和报告：

```powershell
python scripts/run_prompt_evolution_proof.py
```

输出位于 `output/prompt-evolution-proof/`。该实验用于证明“反馈驱动的提示词版本确实改变 Agent 行为并通过隐藏集门禁”，数据来源仍是 `synthetic-controlled`，因此生产来源门禁保持失败；它不应被表述为外部 LLM 权重提升或真实公开 PR 上的生产效果。

### 拒绝路径证明（`output/rejection-proof/`）

上面那个证明只覆盖了门禁的一半：**能通过**。在这个模块加入之前，翻遍
`output/` 下全部历史报告，`decision` 只出现过一个值 `activated`——
**拒绝路径从未在一次端到端回放里执行过**，只有单测直接构造指标字典去戳
`_non_regressing`。而 holdout 门禁是这套系统里唯一的抗过拟合检查。一道
从没打响过的门禁不能算已知可用：它可能因为某个取值口径错误而永远返回
True，报告上什么都看不出来。

```powershell
python scripts/run_rejection_proof.py
python scripts/run_rejection_proof.py --scenario no_improvement
```

刻意**不**用“构造一个分数更低的候选”来凑这个结果——那只证明了比大小能
工作。这里复现的是 holdout 真正要防的那类失效：Validation 的 8 个仓库里
每一处 `set_cookie(` 都恰好是不安全用法（安全写法走
`response.headers["Set-Cookie"]`），于是从反馈里学到的规则退化成**只认
API 名、不看关键参数**。实测结果：

| 指标 | Validation | Holdout |
|---|---|---|
| Precision | 1.0 → 1.0 | 1.0 → **0.4286** |
| Recall | 0.4 → **1.0** | 0.6667 → **1.0** |
| 干净样本准确率 | 1.0 → 1.0 | 1.0 → **0.4286** |
| 综合得分 | 0.7214 → **1.0**（满分） | 0.87 → 0.6257 |

候选在能看见的数据上拿到满分，`validation_improvement` 与
`validation_non_regression` 双双通过，**只有 `holdout_non_regression`
一道门禁把它拦下**（v2 落盘、`parent_version=1`、未激活，上线版本仍是 v1）。

三条口径必须一起读：

- **断言的是“因为哪道门禁被拒”，不只是“被拒了”。** 这个语料第一版跑出来
  是四道门禁一起 False——其中 `evaluation_success` 是构造 `Finding` 时漏了
  必填字段，所有 `set_cookie` 样本直接抛异常。那一版 `decision` 同样是
  `rejected`；若只断言“被拒绝了”，测试会全绿，而真正要证明的东西（门禁靠
  **误报**识别过拟合）一条都没被验证。所以报告里 `failing_gates` 必须与
  预期精确匹配，且 `success_rate` 必须保持 1.0。
- **两个分区分布不同是这个构造的定义，不是缺陷。** 若两边同分布，过拟合
  在验证集上就已经暴露，根本轮不到 holdout 去拦。
- **holdout 上召回率其实是涨的**（0.6667 → 1.0）。一个只看召回率、或只看
  任一单一指标的门禁会**放它过去**。受保护指标是一组而不是一个，原因就
  在这里。

`claim_scope` 随报告落盘，写明它**不**声称：真实候选生成器产出这类过拟合
候选的概率（需要真实反馈流数据，当前 `failure_cases` 为 0 条）；也不声称
覆盖了所有类型的过拟合（此处只覆盖“学到过宽规则”一种）。数据来源同样是
`synthetic-controlled`。

### 闭环流转基建

`POST /v1/evolution/auto` 之前存在一个真实的**断流** bug：LLM 路径固定用
`activation_policy="shadow"`，判决永远不会是 `activated`，因此尾部的
`resolve_failure_cases` 在这条路径上是死代码。同一批反馈每轮被重新喂给
生成器，第二轮开始固定返回“没有新信号”，循环停在原地。这不是“少一个
功能”，是流转本身断了。加上另外两处断裂——`shadow_ready` 无人消费（候选
出不来），以及影子证据攒够之后没有基于证据的判决（候选上得去下不来）——
下面前六件事修的是这三处。第七、第八件各修另一回事：第七件是管道通了但
**里面没有水**（`failure_cases` 0 条），它给反馈找了一个真实来源，并把
"自动对出来的差集"和"人工确认的反馈"之间那道闸门显式化；第八件是**水流
过去时会不会在路上被悄悄倒掉**——按 ACE 的 context collapse 失效模式审计
出的第四个问题。

**1. 消费账本（`evolution_attempts` 表）。** “尝试过”与“已解决”是两个
不同的账本。`failure_cases.resolved` 语义是“这条反馈处理完了”，只在候选
激活时置位；用它兼任“喂过生成器了”会被迫二选一：要么把被拒反馈从分诊
列表里抹掉，要么永远重试。所以单独记账，记录哪条反馈在哪次 run 里被
尝试、判决是什么。查询刻意**不按判决过滤**——被拒意味着“试过且失败”，
重试必须是一次显式的人工动作。

**2. 根因指纹与频率分流。** 指纹是本地纯函数
`sha256(category + rule_id + 归一化 path)`（`evoagent/root_cause.py`），
不是 LLM 聚出来的 ID：后者存在循环依赖（计数要决定是否发起那次产出 ID
的 LLM 调用），且聚类在不同轮次之间漂移，会让频率门禁变得不可复现。
指纹也刻意**不是数据库列**——归一化规则变更时，存下来的副本会与实现
分叉，把一个根因劈成两个桶。低频根因只写记忆，不花掉一次候选生成
＋全量回放。

**3. 候选生成阶段的记忆召回与反思信号。** 生成器会按根因去 semantic
记忆召回既有结论，并拿到这些根因**过去被尝试过什么、门禁怎么判的**。
没有后者，生成器对自己的历史一无所知，会反复提出等价的修改——这正是
[GEPA (arXiv:2507.19457)](https://arxiv.org/html/2507.19457) 的核心
观察：把判决以自然语言反馈回生成器，信息量远大于只给一个标量分数。

注意这**不违反**“记忆不进评测链路”的隔离原则（见 `memory.py` 模块
文档）。那条原则针对被评测 case 的执行过程：跨 case 召回会让第二次的
“发现”变成召回而不是检出，指标朝着我们希望的方向虚高，且 Validation
上的收益会通过记忆漏到 Holdout。这里的注入点在两轮评测**之间**，被
评测的 reviewer 仍然对记忆一无所知。`tests/test_memory_in_evolution.py`
里有一条断言专门钉住这个区分。

**4. 版本档案与选亲（`evoagent/archive.py`）。** 改动之前 baseline 恒等于
当前上线版本，被拒候选存进 `skill_versions` 后再无人问津，`parent_version`
有值但没有任何代码读它选亲——搜索退化成“从当前最优爬一步，爬不上去就
原地不动”。现在版本链与评测记录会合成一份**档案**，含逐样本分数表
（复用 `evolution_runs.metrics.candidate.case_results`，不需要重采数据）。

- [DGM (arXiv:2505.22954)](https://arxiv.org/html/2505.22954v3)：保留档案
  而非单一血统，因为 stepping stones——当下分数平庸的版本可能是后来
  突破的必要祖先。所以没跑过评测的版本也留在档案里。
- GEPA：用聚合分数选亲会淘汰“专才”（总分略低、但在某几个 case 上唯一
  正确的候选携带着别处没有的信息），改在**逐样本 Pareto 前沿**上按领先
  case 数加权采样。

两处刻意的设计：**选亲不动门禁**——门禁基线恒为当前上线版本，它要回答
的正是“能不能替换掉现在这个”；选亲只决定候选的**起点**，不进入
`decision` 的计算。**选亲是确定性伪随机**——种子取本轮根因指纹，同一批
反馈永远选出同一个亲本，因为选亲影响候选内容而候选内容进落盘记录，用
真随机源会让“这次为什么产出了这个候选”再也无法复现。

默认策略是 `active`，即与本节功能加入之前行为完全一致。刻意不默认成
`pareto`：当前 validation 区间宽度 0.15–0.17，“档案里哪个版本更好”这个
判断本身的噪声就比策略之间的差异大，激进选亲很可能只是在噪声里随机
游走，却让人以为在做搜索。基建先就位，切策略等有数据支撑。

**5. 影子放量接线（`ReleaseManager.stage_shadow`）。** 闭环还有第二处
断裂：`auto_propose` 的 LLM 路径判决永远是 `shadow_ready`，但在这之前
**没有任何代码消费这个判决**——候选要真上影子流量，得有人另外去查版本号、
手动 POST 一次 `/v1/deployments/llm-review`。前一段（消费账本）修的是
“反馈进不去”，这一段修的是“候选出不来”。现在 `POST /v1/evolution/auto`
在判决为 `shadow_ready` 时自动放量，结果记在返回值的 `shadow_staging`
里并落审计。

这里**守卫比接线本身更要紧**。`save_deployment` 会把
`samples/errors/shadow_samples/disagreements` 全部重置为 0，而
`record_deployment_result` 的自动回滚门禁正是靠 `samples` 判断的。自动
接线若直接覆盖一个正在跑的部署，就会擦掉正在累积的错误预算——一个刚要
触发回滚的金丝雀会重新变得“干净”，等于用一次自动化把一个安全机制静默
解除，且事后从部署表上看不出曾经有过证据。所以默认是**拒绝而不是覆盖**：

- 已有 running 部署且候选版本不同 → `staged: False`，理由里**点名**会
  丢掉什么（“版本 7 已经跑了 15 个样本”），交给人决定；
- 同一候选版本重复调用是幂等的，不重置已累积的证据（`auto_propose` 可能
  被反复触发，每次重置会让晋升门禁永远攒不够样本，而表面一切正常）；
- 已 `rolled_back` / `promoted` 的部署可以被替换——这道门禁挡的是“正在
  观测中”，不是“曾经存在过”，否则一次回滚会永久堵死这条通路。

`canary_percent` 恒为 0：影子是“跑但不采用其输出”，金丝雀是“真的把结果
给用户”。回放门禁通过只够上影子，让候选直接吃真实流量需要影子阶段的证据
先攒够——两步合成一步就没有任何观测窗口了。`auto_promote` 也不从这里
打开：分歧率低也可能只是候选和基线一起漏了同一批问题，让它独自决定上线
是把一个弱信号当成充分条件。

**6. 影子晋升判决（`ReleaseManager.evaluate_promotion`）。** 闭环第三处、
也是最后一处断裂：候选**上得去、下不来**。第 5 项把候选放上了影子流量，
`observe_shadow` 逐条记着观测，但在这之前全代码库唯一的晋升路径是
`record_shadow_observation` 里的 `auto_promote` 分支，而 `stage_shadow`
刻意把它设成 False（理由见上一段）。于是影子证据只进不出：要么永远停在
影子上，要么靠人手动打开那个开关——而打开它就等于让分歧率独自决定上线，
正是设计 `stage_shadow` 时明确拒绝的做法。这个缺口是我自己留下的。

现在有一个显式端点 `POST /v1/deployments/llm-review/promote`，返回
**三态**判决（`promote` / `reject` / `insufficient_evidence`）与理由，
不满足条件时不写库。四条口径：

- **低分歧率不能当通过条件。** 候选和基线一起漏掉同一批问题时分歧率是
  0.0，完美通过任何“分歧率 ≤ 阈值”的门禁——一个什么都没改进的候选会因此
  自动上线。所以通过条件另立一条：候选至少要产出过基线漏掉的发现
  （`candidate_wins ≥ min_wins`）。
- **对称分歧率也不能当否决条件。** `len(primary ^ candidate) / len(union)`
  分不出“候选多报了一条”和“候选漏掉了基线报过的一条”，而这两者风险相反。
  一个每次都多报一条真问题的候选对称分歧率是 1.00，会被当成退化拦下。
  所以 `release_observations` 新增了 `candidate_only` / `primary_only` 两列，
  门禁看的是 `loss_rate`（漏掉基线发现的观测占比），对称分歧率只作展示。
  这条是写完判决逻辑跑测试时才暴露的——原本的实现确实在用对称分歧率否决。
- **证据必须能归属到具体候选版本。** `save_deployment` 只清零 deployments
  上的计数器，`release_observations` 的历史行是留着的。新增
  `candidate_version` 列并按它过滤，否则换一个候选之后上一个候选的观测会被
  算进新候选的晋升证据里，报告上完全看不出来。这一列加入之前的旧行是
  NULL，**不计入**任何候选——无法归属的证据不猜。
- **分母纪律与三态。** `samples == 0` 时各项 rate 返回 `None` 而不是 0.0
  （0.0 会直接满足“≤ 阈值”，把“一个样本都没有”伪装成“测过了，很干净”）；
  `insufficient_evidence` 与 `reject` 分开，把“没测够”和“测了不合格”合成
  同一个 False 会让一个还没攒够样本的候选看起来像被否决过。

晋升写回走增量 UPDATE 而不是 `save_deployment`：后者会清零计数器，晋升时
清零等于把刚刚用来做决定的那批证据擦掉，事后无法复核这次晋升凭什么发生。
写回前还会再校验一次候选版本，判决与写回之间若有人换了候选就返回
`insufficient_evidence` 要求重新判决，不把 A 的证据用到 B 的晋升上。

判决通过时理由里如实写着：候选独有的发现**不是已确认的真阳性**——影子期
没有人工标注，无法区分“候选更准”和“候选误报更多”。`candidate_wins` 只是
“候选在做事”的弱信号，不把它表述成“候选更准确”。

**7. 反馈入口（`evoagent/feedback_import.py`）。** 前六项把管道接通了，
但管道里没有水：`failure_cases` 是 0 条，于是档案的逐样本分数为空
（`versions_evaluated` 为 0，Pareto 前沿是空的）、选亲策略切到 `pareto`
也无事可做。唯一现成的真实来源是 D6 回放——173 个真实 PR 样本的模型输出
逐条存在 checkpoint 里，和数据集的 `expected_findings` 一对就是差集。

**但自动对出来的差集不是反馈。** 这不是谨慎，是本仓库已经写下的口径：
`tiered_match` 的文档写着 `unlabelled`（落在标注之外的 finding）**不等于
误报**——数据集只标注了反转出来的那个种子缺陷，仓库里可能真有别的问题，
reviewer 指出它们是对的；`datasets/labelling-r1.json` 那 88 条人工标注里
83 条是 `valid`，实测支持这一点。把它们当 `false_positive` 灌进去，等于
教模型别再报真问题。漏报一侧也不干净：`label_provenance` 是
`title-keyword` 79 / `linked-issue` 44 / `cve` 2（按候选计），“PR 标题里
有 fix 字样”不等于“人类确认 reviewer 本该在这里报警”。

轨道 C 已经为这件事立过规矩（PR 关闭事件推断出的类别叫
`merged_without_addressing` 而不是 `false_positive`，并被
`HUMAN_CONFIRMED_CATEGORIES` 白名单挡在提示词进化之外）。要绕过那道
白名单不需要改它，只要在写库时把推断结果写成一个字面合法的 category
就够了。所以这里是**两步，中间隔着人**：

```bash
python scripts/import_replay_feedback.py derive --replay output/real-pr-regression/d6-replay.checkpoint.jsonl --out datasets/feedback-candidates-d6.json --stamp 2026-09-07
```

派生出的候选 `label` 一律为空，两类候选分别叫 `unmatched_expected` /
`unmatched_finding`——刻意不叫 `missed_issue` / `false_positive`，那是
**确认之后**才能用的词。人工填完标签后 `import` 才写库，且拒绝三类：
未确认的（label 为空）、标签不属于该类候选的、以及确认为 `valid` /
`valid-but-noise` / `not-expected` 的（前两者说明模型报对了，后者说明
数据集标注偏严，都不是模型的错误）。

其余几条口径：

- **cwe 不冒充 rule_id。** `auto_propose` 会把 `payload.finding.rule_id`
  拼成 `[focus-rule:X]` 注入提示词，而数据集的 expected_findings 没有
  rule_id 只有 cwe——`CWE-193` 恰好能通过 `FEEDBACK_RULE_ID` 那个正则。
  拿它顶替会注入一条没有任何 reviewer 认识的规则，指标不动，然后被改进
  门禁判成“模型学不动”，实际是这里造了个假字段。所以 rule_id 留空给人填。
- **默认只取 validation。** holdout 的反馈进提示词进化等于拿隐藏集调参，
  门禁当场失效。
- **回放里失败的 case 跳过，不当成零 findings。** 零 findings 意味着
  “模型看过并认为没问题”，会凭空造出一批漏报候选。
- **盲标是不对称的。** 判“是不是误报”必须盲（看到真值就是看答案）；判
  “该不该报”不能盲（不给出缺陷就无从判断），它的偏倚风险在数据集标签本身，
  所以每条候选都带着 `label_provenance` 一起给人看。
- 导入时顺手把样本 diff 存进 `task_payloads`——`failure_cases` 表没有 diff
  字段，而轨道 F 把反馈提升成数据集样本必须有 diff。diff 由调用方从数据集
  传入而不是从候选文件里读：候选文件只带片段，拿片段冒充完整 diff 会给
  轨道 F 埋一个看起来完全正常的截断输入。

当前状态：对 D6 回放跑出 **194 条候选**（125 条 unmatched_expected /
69 条 unmatched_finding，覆盖 71 个样本，全部成功定位到 diff 片段），
落在 `datasets/feedback-candidates-d6.json`。**尚未人工标注，因此
`failure_cases` 仍是 0 条**——`import` 对这批未确认候选返回
`skipped_unconfirmed: 194`、写库 0 条，这是设计如此，不是没跑通。

人工那一步有工装，但工装**不产出任何 label**：

```bash
python scripts/import_replay_feedback.py worksheet --candidates datasets/feedback-candidates-d6.json --out output/feedback-labelling/worksheet-expected.md --kind unmatched_expected --size 30 --seed 20260907
python scripts/import_replay_feedback.py apply-worksheet --candidates datasets/feedback-candidates-d6.json --worksheet output/feedback-labelling/worksheet-expected.md
```

`worksheet` 按固定种子确定性抽一小批（与 `alert_labelling.sample_alerts`
同一做法：先按 candidate_id 排序再抽，否则上游一改顺序、同一种子就抽到
另一批，已标好的标签全部作废），渲染成一份带 diff 片段、`label:` 列留空
的 Markdown 清单；`apply-worksheet` 把填好的清单写回候选文件。**不要求人
去手改那个 194 条的嵌套 JSON**——在嵌套 JSON 里填 label 最容易填错位置，
而填错位置的表现是一条判定被挂到别人身上。`--kind` 默认只出一类：两类
候选问的问题不同、盲标要求不同，混在一份清单里让人来回切换判据。

写回同样是"宁可报错也不猜"：清单里出现未知 candidate_id（清单来自上一版
候选）时**整份拒绝**而不是部分写回——那时其它条目的归属也不可信；已有
非空 label 的候选不被覆盖，重标必须是显式动作。

**为什么不由程序把这 30 条标掉。** 一条由程序写出来的 label 是推断结论，
而两步之间那道闸门的全部意义就是推断结论不得进 `failure_cases`。填了
label 列，`HUMAN_CONFIRMED_CATEGORIES` 那道白名单依然会放行，因为它检查
的是 category 字面是否合法，而不是背后的数据是不是真的有人看过。所以
`failure_cases` 现在仍是 0 条，这个数字是诚实的。

**7b. 反馈提升成评测样本（`evoagent/case_promotion.py`，轨道 F）。**
提升的目标是 store 里的 `evaluation_cases` 表（`_propose` 每轮真正拿来
打分的东西），**不是** `datasets/*.jsonl`——后者是权威输入语料，不得静默
重新生成。三个口径问题的定案：

- **`bad_fix` 拒绝提升，并在报告里写明原因。** 受保护指标
  （`score` / `precision` / `recall` / `high_severity_recall` + 条件性的
  `severity_accuracy` / `clean_accuracy`）全是**检出**指标，一条"发现对了
  但修复建议是错的"反馈提升成样本之后对任何指标都没有影响。不选"加一个
  `fix_quality` 指标"是因为数据集里没有修复建议的真值，那会造出又一个
  `completeness` 式的空指标；不选"静默跳过"是因为被静默丢掉的反馈和被
  评估过后判定不该提升的反馈，在报告上长得一模一样。
- **`false_positive` 只能从本身干净的源样本提升成负样本。**
  `real-pr-v1.jsonl` 每条样本都是反转 fix PR 得来的，diff 里含着种子缺陷；
  配上空 `expected_findings` 写进评测集，断言的是"这里不该报任何东西"，
  而那是假的——"报对了真缺陷"会被记成 clean_accuracy 上的一次失败，方向
  正好教反。所以源样本带真值时拒绝，理由写清。
- **split 跟随仓库在语料里已有的一侧，查不到就拒绝，落在 holdout 一侧
  也拒绝。** 前者防的是 `test_repositories_do_not_cross_the_split_boundary`
  钉住的约束（一个仓库同时出现在两边，holdout 就不再是"没见过的分布"），
  后者防的是拿隐藏集调参。

判定与写入分开（`plan_promotions` / `apply_promotions`），因为"这批反馈里
有几条能提升、被拒的各是什么理由"必须能在不动数据库的前提下看一遍。
幂等靠 `save_evaluation_case` 的名字不可变语义；同名不同内容**不吞**，
记成 conflict——它意味着这次算出了不同的样本内容，静默覆盖会让评测集与
它声称的来源不一致。脚本：

```bash
python scripts/promote_failure_cases.py --db evoagent.db --dataset datasets/real-pr-v1.jsonl --clean-dataset datasets/real-pr-clean-v1.jsonl --dry-run
```

`failure_cases` 现在 0 条，所以这一层**跑出来必然是空计划**。它现在只有
单测覆盖（`tests/test_case_promotion.py`，25 个用例），能证明的是"口径已
定案且被钉住"，不是"在真实反馈上跑过"。

**8. 已验证规则的保留清点（`evoagent/prompt_rules.py`）。** 这一项修的
不是断流，是**流过去的东西会不会在路上被悄悄倒掉**。

`auto_propose` 每轮把学到的条目追加到亲本末尾的 "Learned constraints:"
块，而 `_generate_candidate` 把**整个**亲本交给生成器、拿回一个**完整
重写**的候选。累积 + 整体重写 = 迭代重写，即
[ACE (arXiv:2510.04618)](https://arxiv.org/pdf/2510.04618) 指出的
**context collapse**。这个缺口是照着论文去审计自己代码查出来的，不是
照搬论文结构。

现有门禁的两处缝隙都已用测试钉住（`tests/test_prompt_rules.py` 里的
`ExistingGateBlindnessTests` 是**刻画测试**，断言的是缺口当前确实存在）：

- `safety_evaluate` 只数 `diff/severity/fix/test/json` 五个通用 token 算
  `completeness`。它问的是“这还像不像一个 review 提示词”，不是“之前验证过
  的规则还在不在”。一个删光三条已验证规则的候选，completeness 仍是 1.0、
  safety 门禁照过——测试断言的正是这一点。
- holdout 门禁只**部分**兜住。纯粹丢失会掉分被拒，但理由写的是“a protected
  metric regressed”，不会说“你删掉了三条已验证规则”，同一根因于是被反复
  重试。真正漏掉的是另一种：丢两条旧规则、加一条更强的新规则，净分数**上升**，
  门禁放行，三代积累悄悄少了两条，报告上完全看不出。

清点是**纯函数**，不经 LLM——拿一个有 collapse 问题的东西去检测 collapse
没有意义。锚点用现成的 `[focus-rule:X]` 标记（`auto_propose` 当初写它就是
为了“machine-auditable in offline replay”）。`retention_gate` 三态：
基线一条标记规则都没有时返回 `None` 而不是 True——一个恒为 True 的门禁在
报告上与真门禁长得一模一样，而它什么都没挡住。删除本身不禁止，**静默**
删除才禁止：确认某条规则是错的，就把 rule_id 显式列进 `allow_dropping`。
这与 `stage_shadow` 默认拒绝而非覆盖同源——静默丢失证据比丢失本身更危险。

**这道门禁是必要的，不是充分的**，README 里必须这样写：它清点的是标记过的
规则条目，不是提示词的全部语义。一个候选可以在不删任何标记的前提下把某条
规则的正文改写得失效——`dropped_constraints` 会把正文变更如实报出来交给人
看，但函数本身判断不了改写是等价还是削弱。把它表述成“保证什么都没丢”就是
又造一个 `completeness` 式的假门禁。

**这个模块有两半，方向相反。** 上面那一半（`inventory` / `diff_rules` /
`retention_gate`）是**事后清点**：候选已经生成出来了，去数它丢了什么。
它能发现 collapse，但发现的时候那次 LLM 调用已经花掉了。

第二半（`make_entry` / `apply_delta` / `compose_prompt`）是**事前构造**，
即 ACE delta 机制里唯一真正重要的那一条：**让 LLM 决定“改什么”，让代码
决定“改完之后集合是什么”。** 已验证规则结构化成条目（带来源 `run_id` 和
它当初通过的门禁），生成器只能产出 `add` / `replace` / `drop` 三种操作，
合并由纯函数完成。走这条路径时，collapse 的那个形态——“丢两条旧规则、加
一条更强的新规则、净分数上升”——**无法表达**：一个只说“加一条”的 delta，
合并结果必然仍含那两条旧规则；要丢就得显式写 `drop`，而 `drop` 必须给
理由（`validate_delta` 挡住没有 reason 的删除）。

两半都要留着：现存 v1..vN 提示词全是纯文本，只能靠上半截清点；
`entries_from_prompt` 负责把它们抬举成条目，新走 delta 路径的才享受下半截
的保证。

实现时刻意做成三处“宁可报错也不猜”：非法 delta **整个拒绝、不部分合并**
（部分合并会产出一个“看起来正常但少了一条”的条目集，症状与 collapse 一模
一样却更难查）；`add` 一条已存在的规则被拒而不是静默覆盖或静默忽略；同一
rule_id 在一个 delta 里出现两次被拒，因为结果会取决于应用顺序，而“确定性
合并”要排除的正是这个。出处标记 `[src:]` / `[gates:]` 在比对前被剥掉——
换个出处不算改了规则，否则这道门禁会在第一次重新渲染时误报，然后被当成
噪声关掉。

**两条线都已接进生产路径（2026-09-07）。** `retention_gate` 进了 `_propose`
的 `gates`，但**是纯报告项，不进 `decision`**——与 `significant` /
`holdout_significant` 同一档，且刻意**不**加进
`rejection_proof.GATE_NAMES`（那是个白名单，加进去会让 `_failing_gates`
把一个纯报告项算成门禁失败）。这样处理是因为 `None`（基线无标记规则，包括
全部现存 v1 提示词）两种收法都是错的：当 True 会让门禁在最常见的情形下
静默失效，当 False 会把第一次进化直接拦死。先让"这个候选删了哪几条规则"
出现在每次 run 的记录里，积累几轮真实数据之后再决定要不要升格成硬门禁。
delta 合并层同时接进了 `auto_propose`：非 LLM 路径不再盲目追加，而是
`entries_from_prompt` → `apply_delta` → `compose_prompt`，所以候选提示词
里只有**一个** "Learned constraints:" 块，且第二轮学习可证明地保留第一轮
的规则（`test_a_second_round_keeps_the_first_rounds_rule`）。

诚实标注：以上八项**都只有单测覆盖，没有真实生产数据跑过**。
`failure_cases` 里目前 0 条真实线上反馈——第 7 项把候选派生出来了，但
人工确认那一步没做，所以“流转是通的”这个结论的证据强度仍然是“单测证明了
链路不会再卡住”，不是“在真实反馈流上验证过”。
另外 `api.py` 里那两段桥接本身尚无测试覆盖，被覆盖的是它们调用的
`stage_shadow`（含全部守卫分支）与 `evaluate_promotion`（21 个用例）；
第 7 项由 `tests/test_feedback_import.py`（31 个用例）覆盖。

## Skill 自进化

Skill 自进化与提示词进化是两套独立版本链。系统不会把反馈直接拼成 Python 执行，而是生成无主机权限的声明式 Skill artifact。artifact 可以新增确认漏报规则或移除确认误报规则，并包含父版本、内容 SHA-256、评测分数和激活状态。

`POST /v1/skill-evolution/auto` 从当前租户未解决反馈生成候选。漏报反馈应携带 `finding.rule_id`、`severity`、`path` 和 `line`；系统优先使用 `finding.evidence`，缺失时从原任务 Diff 的对应新增行提取字面匹配证据。候选只有在 Validation 获得最小提升、受保护指标不退化且 Holdout 非退化时才会自动激活并解析所使用的反馈。被拒绝或样本不足的版本仍会保存供审计，但不会进入审查链路。

也可以向 `POST /v1/skill-evolution/propose` 提交人工构造的候选：

```json
{
  "skill_name": "evolved-review",
  "artifact": {
    "name": "evolved-review",
    "description": "Confirmed project-specific review rules",
    "rules": [{
      "rule_id": "SEC-DANGEROUS-CALL",
      "severity": "high",
      "match": "dangerous_call(data)",
      "title": "Dangerous call",
      "explanation": "A confirmed unsafe API was added.",
      "fix": "Use the constrained API.",
      "test": "Add a regression test."
    }]
  }
}
```

激活后服务会把 `evolved-review@<version>` 作为声明式 Tool/Scanner 加入当前租户的模式路由器。artifact、激活版本、进化运行和运行时注入均按租户隔离；重启、`/v1/skills/reload` 和版本回滚都会从数据库恢复相应 artifact。Skill 名称必须以 `evolved-` 开头，规则只支持新增行上的受限字面匹配，不支持任意代码、正则表达式或主机权限。

相关门禁可通过以下环境变量调整：

- `EVOAGENT_EVAL_MIN_CASES`：验证集最少样本数；
- `EVOAGENT_EVAL_MIN_HOLDOUT_CASES`：隐藏集最少样本数；
- `EVOAGENT_EVAL_MAX_CASES`：每个数据分区单次最多回放样本数；
- `EVOAGENT_EVAL_MIN_IMPROVEMENT`：验证集最小分数提升；
- `EVOAGENT_EVAL_MAX_METRIC_REGRESSION`：受保护指标允许的最大退化，默认 `0`。

闭环流转相关（见上文「闭环流转基建」）：

- `EVOAGENT_EVOLUTION_ROOT_CAUSE_MIN_OCCURRENCES`：一个根因指纹要出现
  几次才够格触发候选生成＋全量回放，默认 `1`（＝与本功能加入之前行为
  一致）。低于这个数只写记忆；
- `EVOAGENT_EVOLUTION_MAX_ATTEMPTS_PER_ROOT_CAUSE`：同一根因最多尝试
  几次，默认 `3`，`0` 表示不限制。反复尝试反复失败说明“改提示词”对
  这类根因无效；
- `EVOAGENT_EVOLUTION_PARENT_STRATEGY`：选亲策略，`active`（默认）/
  `best` / `pareto` / `epsilon_greedy`。拼错会在启动时报错而不是静默
  跑成 `active`；
- `EVOAGENT_EVOLUTION_PARENT_EPSILON`：`epsilon_greedy` 的探索概率，
  默认 `0.1`，仅该策略下生效。

## GitHub Webhook

项目使用“GitHub 仓库 Webhook + 公网转发 + fine-grained PAT”接收 PR 事件，不需要创建或安装 GitHub App：

```text
GitHub Pull request 事件
        │
        ▼
https://<公网域名>/webhooks/github
        │  公网转发
        ▼
http://127.0.0.1:8080/webhooks/github
        │
        ▼
EvoAgent 创建异步审查任务
```

### 1. 配置 EvoAgent

先生成一个 Webhook Secret，并根据需要配置 GitHub fine-grained personal access token：

```powershell
$webhookBytes = New-Object byte[] 32
[Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($webhookBytes)
$env:EVOAGENT_GITHUB_WEBHOOK_SECRET = [Convert]::ToBase64String($webhookBytes)

# 私有仓库、PR 评论回写或自动修复需要；只审查公开仓库且不回写时可以不配置。
$env:EVOAGENT_GITHUB_TOKEN = '<GitHub fine-grained PAT>'

# 默认关闭。设为 true 后，审查完成时更新或创建 PR 评论。
$env:EVOAGENT_AUTO_POST_REVIEW = 'true'

python -m evoagent
```

Webhook Secret 用于验证 GitHub 请求头中的 HMAC-SHA256 签名，不能与登录用的 `EVOAGENT_AUTH_SECRET` 混用。Webhook 请求不携带管理台 Bearer Token；`/webhooks/github` 使用签名而不是用户登录进行认证。

fine-grained PAT 只授权需要接入的仓库，并按功能授予最小权限：

- 读取私有仓库 PR Diff：`Contents: Read`、`Pull requests: Read`；
- 回写审查评论：`Pull requests: Read and write`；
- 创建自动修复分支和提交：`Contents: Read and write`、`Pull requests: Read and write`。

只接收 Webhook 但不访问私有仓库、不回写评论且不执行自动修复时，可以不设置 PAT。密钥必须在启动 EvoAgent 前设置，修改后需要重启服务。

### 2. 建立公网转发

GitHub 无法访问 `127.0.0.1`，需要把公网 HTTPS 地址转发到本地 `http://127.0.0.1:8080`。任选一种已安装的转发工具，例如：

```powershell
# Cloudflare Quick Tunnel
cloudflared tunnel --url http://127.0.0.1:8080

# 或 ngrok
ngrok http 8080
```

命令启动后会显示一个形如 `https://example.trycloudflare.com` 或 `https://example.ngrok-free.app` 的公网 HTTPS 地址。保持 EvoAgent 和转发进程同时运行。临时公网地址通常会在转发工具重启后变化，变化后必须同步更新 GitHub Webhook 的 Payload URL。

上述快捷转发会把 8080 端口上的管理台和 API 一并暴露到公网，因此必须保持 `EVOAGENT_AUTH_REQUIRED=true`，并使用强管理员密码和随机 `EVOAGENT_AUTH_SECRET`。长期部署建议通过反向代理只公开 `/webhooks/github`（以及按需公开 `/health`），不要向公网暴露整个管理台。

### 3. 在 GitHub 仓库中添加 Webhook

进入目标仓库的 **Settings → Webhooks → Add webhook**，填写：

- **Payload URL**：`https://<公网域名>/webhooks/github`；
- **Content type**：`application/json`；
- **Secret**：与 `EVOAGENT_GITHUB_WEBHOOK_SECRET` 完全相同；
- **SSL verification**：保持启用；
- **Which events would you like to trigger this webhook?**：选择 **Let me select individual events**，只勾选 **Pull requests**；
- **Active**：保持勾选。

EvoAgent 会处理 `opened`、`reopened` 和 `synchronize` 三种 PR 动作；服务会根据 payload 中的 `diff_url` 下载 Diff，并异步创建审查任务。

`closed` 动作只在 `EVOAGENT_INFER_FEEDBACK_FROM_MERGE=true` 时被处理（默认关闭），用于把"PR 带着我们报的问题被合并了"记成一条**弱**反馈信号。其他 `pull_request` 动作会正常接收但被忽略。

这个信号的口径必须写清楚，否则它很容易被当成"误报被确认"：

- 类别是 `merged_without_addressing`，**不是** `false_positive`。人工反馈的四个类别意味着"人看过并确认了"，推断结果写进同一个字段，下游就再也分不出哪条有人背书。
- 它**不驱动**提示词进化。`auto_propose` 用白名单只接人工确认的类别，推断条目落盘、计数、可供人工分诊，被排除的条数在返回值的 `inferred_cases_excluded` 里如实报出。
- 至少三条混淆同时存在：维护者可能明知有问题仍然合并；`EVOAGENT_AUTO_POST_REVIEW` 关闭时报告根本没出现在 PR 上（这个前提随信号一起落盘为 `review_was_visible_on_pr`）；合并前的 commit 可能已经顺手修掉了。
- 关闭但未合并不产出任何信号——PR 被弃掉的原因与代码质量基本无关。审出 0 条的 PR 合并了也不记：那是弱正例，混进同一个类别会让这个数失去方向性。

### 4. 验证连接

先确认本地服务和公网地址都能访问健康检查：

```powershell
Invoke-RestMethod http://127.0.0.1:8080/health
Invoke-RestMethod https://<公网域名>/health
```

然后新建 PR、重新打开 PR，或向 PR 推送一次提交。在 GitHub 的 **Settings → Webhooks → Recent Deliveries** 中应看到 `/webhooks/github` 返回 `202`；管理台的任务中心随后会出现对应审查任务。如果失败，优先检查公网转发进程是否仍在运行、Payload URL 是否包含 `/webhooks/github`、Secret 是否一致，以及 PAT 是否有目标仓库权限。

默认只在管理台保存结果。只有 `EVOAGENT_AUTO_POST_REVIEW=true` 时才会向 PR 回写评论。

自动修复只覆盖可确定安全的规则，例如调试输出、`shell=True` 和硬编码 Python 凭据；结果始终提交到新的 `evoagent/fix-pr-*` 分支，不直接修改源分支。

## 完整生产模式

```powershell
Copy-Item .env.example .env
docker compose up --build
```

Compose 会启动 Redis 和 EvoAgent。两个后端的退化行为**不一样**，这是刻意的：

- 不配 `EVOAGENT_REDIS_URL`：退回进程内线程队列（同样有 ACK、租约、
  指数退避与死信队列，只是不跨进程），适合本地演示
- 配了 `EVOAGENT_DATABASE_URL` 指向 PostgreSQL：直接抛 `NotImplementedError`

区别在于**静默降级会不会骗人**。队列退回内存后语义仍然成立，跑起来的东西
和你以为的一样；而存储退回 SQLite 时，你以为数据进了 Postgres，实际写在本地
文件里——同一个"自动退回"，一个安全，一个是事故。所以后者宁可起不来。

## API

| 方法 | 路径 | 说明 |
|---|---|---|
| `GET` | `/health` | 健康检查 |
| `POST` | `/v1/auth/login` | 登录并获取租户绑定的短期 Bearer Token |
| `POST` | `/v1/reviews` | 创建同步审查任务 |
| `POST` | `/v1/reviews?async=true` | 创建异步审查任务 |
| `GET` | `/v1/tasks/{id}` | 获取状态、轨迹和报告 |
| `GET` | `/v1/tasks/{id}/report` | 获取 Markdown 报告 |
| `GET` | `/v1/tasks/{id}/feedback` | 获取该已完成任务的反馈历史 |
| `POST` | `/v1/tasks/{id}/fix` | 创建自动修复分支和提交 |
| `POST` | `/v1/tasks/{id}/feedback` | 回流误报、漏报或坏修复 |
| `POST` | `/v1/tasks/{id}/cancel` | 请求取消任务 |
| `POST` | `/v1/tasks/{id}/resume` | 从最近 checkpoint 续跑任务 |
| `POST` | `/webhooks/github` | 接收 GitHub PR webhook |
| `POST` | `/v1/skills/reload` | 动态重新加载 Skill |
| `POST` | `/v1/evolution/auto` | 从失败案例生成并评测提示词版本 |
| `POST` | `/v1/evolution/propose` | 评测指定提示词候选版本 |
| `GET/POST` | `/v1/evaluation/cases` | 查询或增加版本化评测样本 |
| `GET` | `/v1/evolution/status` | 查询模型与评测门禁就绪状态 |
| `GET` | `/v1/evolution/runs` | 查询持久化的新旧版本评测记录 |
| `POST` | `/v1/skills/{name}/versions/{version}/activate` | 激活或回滚版本 |
| `POST` | `/v1/skill-evolution/auto` | 从确认反馈生成、回放并门禁 Skill 候选 |
| `POST` | `/v1/skill-evolution/propose` | 评测指定声明式 Skill artifact |
| `GET` | `/v1/skill-evolution/status?skill_name={name}` | 查询 Skill 门禁与激活版本 |
| `GET` | `/v1/skill-evolution/runs` | 查询 Skill 进化运行与指标 |
| `GET` | `/v1/skill-evolution/{name}/versions` | 查询 Skill artifact 版本链 |
| `POST` | `/v1/skill-evolution/{name}/versions/{version}/activate` | 激活或回滚 Skill artifact |
| `GET` | `/metrics` | Prometheus 文本指标 |
| `GET` | `/api/alerts` | 查询租户告警 |
| `GET` | `/api/audit` | 查询租户审计日志 |
| `GET` | `/api/queue/dead-letters` | 查询死信任务 |
| `POST` | `/v1/queue/dead-letters/replay` | 重放死信任务 |
| `GET/POST` | `/api/deployments/llm-review`、`/v1/deployments/llm-review` | 查询或配置灰度/影子发布 |
| `POST` | `/v1/deployments/llm-review/promote` | 按影子证据判决晋升（三态并附理由，不满足条件时不写库） |

`POST /v1/reviews` 的 `diff` 最大默认 1 MiB；单任务默认最多 8 步、120 秒。可通过环境变量调整，详见 `.env.example`。

完成审查后，可在任务详情的“审查反馈”区域提交 `false_positive`、`missed_issue` 或 `bad_fix`。接口要求任务已成功完成，并会将反馈按任务、租户保存；`missed_issue` 建议附带 `finding.rule_id`、`path` 和 `line`，以便后续候选学习准确的检查目标。

## 架构

```text
HTTP / GitHub Webhook
        │
        ▼
 ReviewService ── TaskStore(SQLite)
        │
        ▼
 ReviewHarness (EvoAgent Runtime / checkpoint / resume / budget / trace)
        │
        ├── DiffParser
        ├── Redis Streams / ACK / lease / retry / DLQ
        ├── ContextManager (unified token budget / iterative context compression)
        ├── MemoryManager (working / episodic / semantic / consolidation / expiry)
        └── ModeRouter
              ├── rules-only：规则/声明式 Scanner → Gates
              ├── hybrid：Scanner + 单 LLM Agent → Gates
              └── agentic：四个真实 LLM 角色 → Gates
                    ├── Planner：动态任务图
                    ├── Security：输入/权限/敏感数据/危险调用链
                    ├── Correctness/Reliability：状态/异常/并发/资源/兼容性
                    └── Critic：盲审、反例与缺失证据
```

Harness 由项目内 `AgentRuntime` 控制状态流转：`PENDING → PLANNING → EXECUTING → REVIEWING → SUCCESS`。只有 `hybrid` 和 `agentic` 会进入模型决策循环；每个角色都有独立 system prompt、上下文、工具白名单、Token/时间预算和调用轨迹。工具层负责仓库搜索、符号/调用关系、测试定位、配置与权限、AST、Git、静态检查与隔离副本执行；Gate 层负责格式、证据、置信度和发布资格。报告直接持久化真实模型/工具调用与 Token 成本。
