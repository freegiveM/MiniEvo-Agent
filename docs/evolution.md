# 评测与提示词进化

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

