# EvoAgent 后续开发计划（交接文档）

本文档是给**另一个对话**的交接件，因此刻意自包含：所有结论都给出代码位置，
所有"建议这样做"都附上"不这样做会怎样"。读者不需要看之前的对话。

写作日期：2026-09-06。**更新：2026-09-07 第三轮**（轨道 G / H 基建 / I 全部
完成并已接线；轨道 F 的三个口径全部定案并实现；第 13 节 D 的标注已由**模型**
完成并落在 scratch 副本上；闭环第一次在真实数据上端到端跑通；新增第 16 节
"第三轮：模型标注 + 第一次真实进化轮"）。
基线状态：`python -m pytest tests/ -q` → **824 passed**
（原 682 → 769 → 775 → 821），第三轮新增 `ForbiddenTokenBoundaryTests` 3 用例。

---

## 0. 一句话现状

闭环有四段：**反馈进来 → 生成候选 → 门禁判决 → 候选上线**。
~~第四段的后半（影子证据 → 晋升判决）**是断的**~~ ——**2026-09-07 更新：
四段现在都通且有单测覆盖**（轨道 G 已完成，见第 12 节）。
但 `failure_cases` 里**真实线上反馈仍是 0 条**（194 条候选已派生，人工标注
未做），所以一切"流转是通的"结论，证据强度都只是"单测证明链路不会再卡住"。

这两句话必须一起读。任何后续文档、README、简历 bullet 都不要只写前一句。

---

## 1. 已完成（有单测覆盖）

| # | 内容 | 修掉的真实缺陷 |
|---|---|---|
| 1 | 消费账本 `evolution_attempts` 表 | **反馈进不去**：`auto_propose` 的 LLM 路径硬编码 `activation_policy="shadow"`，判决永远不是 `activated`，尾部 `resolve_failure_cases` 是死代码，第二轮起固定返回"没有新信号" |
| 2 | 根因指纹与频率分流（`evoagent/root_cause.py`） | 用 LLM 聚类存在循环依赖（计数要决定是否发起那次产出 ID 的调用）且轮次间漂移 |
| 3 | 候选生成阶段的记忆召回 + GEPA 式反思信号 | 生成器对自己历史一无所知，反复提等价修改 |
| 4 | DGM/GEPA 版本档案与逐样本 Pareto 选亲（`evoagent/archive.py`） | 搜索退化成单血统爬山；被拒候选存进 `skill_versions` 后再无人问津 |
| 5 | `ReleaseManager.stage_shadow`（`evoagent/rollout.py:20`） | **候选出不来**：`shadow_ready` 判决无人消费 |
| 6 | 拒绝路径证明（`evoagent/rejection_proof.py`） | holdout 门禁——全系统唯一的抗过拟合检查——从未在端到端回放里打响过 |

### 第 6 项的结果值得单独记录

改动前，`grep -rho '"decision": *"[a-z_]*"' output/` 只返回
`1 "decision": "activated"`。现在是 `1 activated / 2 rejected`。

实测数字（`output/rejection-proof/rejection-proof.json`）：

| 指标 | Validation | Holdout |
|---|---|---|
| Precision | 1.0 → 1.0 | 1.0 → **0.4286** |
| Recall | 0.4 → **1.0** | 0.6667 → **1.0** |
| 干净样本准确率 | 1.0 → 1.0 | 1.0 → **0.4286** |
| 综合得分 | 0.7214 → **1.0**（满分） | 0.87 → 0.6257 |

候选在能看见的数据上拿满分，`validation_improvement` 与
`validation_non_regression` 双双通过，**只有 `holdout_non_regression`
一道门禁拦下它**。

**接手时请保留这三条口径**，它们不是修辞：

1. **断言"因为哪道门禁被拒"，不只断言"被拒了"。** 这个语料第一版跑出来是
   四道门禁一起 `False`——其中 `evaluation_success` 是构造 `Finding` 时漏了
   必填的 `test` 字段，所有 `set_cookie` 样本直接抛异常。那一版 `decision`
   **同样是 `rejected`**：若只断言"被拒绝了"，测试会全绿，而真正要证明的
   东西（门禁靠**误报**识别过拟合，不是靠崩溃压低指标）一条都没被验证。
   所以 `_failing_gates` 必须与预期精确匹配，且断言 `success_rate == 1.0`。
2. **`gates` 字典里不是每一项都是门禁。** `significant` /
   `holdout_significant` 是 Track E 的纯报告项，三态，`decision` 完全不看
   它们（见 `evolution.py` 的 `_significance_report` 文档）。所以
   `rejection_proof.GATE_NAMES` 是**白名单**，且 `None` 不算失败。
3. **holdout 上召回率其实是涨的**（0.6667 → 1.0）。一个只看召回率、或只看
   任一单一指标的门禁会**放这个候选过去**。受保护指标是一组而不是一个，
   原因就在这里。

---

## 2. 轨道 G — 影子晋升判决（~~最高优先级~~ **已完成 2026-09-07**）

> **本节保留原文作为缺口记录，不再是待办。** 实现落在
> `ReleaseManager.evaluate_promotion` / `POST /v1/deployments/llm-review/promote`
> / `tests/test_shadow_promotion.py`。下面口径 1 只写了对称的一半，第 12 节
> 记录了补上的另一半。

### 缺口是真实的，已查证

`evoagent/rollout.py` 只有 6 个方法：`__init__` / `configure` /
`stage_shadow` / `assignment` / `observe` / `observe_shadow`。
**没有 `promote()`。** `grep -rn "promote(" evoagent/*.py | grep -v "def \|auto_promote"`
返回空——没有任何调用者。

全代码库唯一的晋升路径在 `evoagent/store.py:1326` 附近，内联在
`record_deployment_result` 的事务里，前提是 `auto_promote=1`。而
`stage_shadow` 刻意把它设为 `False`（理由仍然成立：分歧率低也可能只是候选
和基线一起漏了同一批问题）。

**净结果：候选能上影子流量，但下不来。** 影子证据攒够之后没有任何基于证据
的晋升判决，只能靠人手动 POST 打开 `auto_promote`——而那等于把弱信号当成
充分条件，正是 `stage_shadow` 当初拒绝的做法。这一段是上一轮开发自己留下
的缺口，不是历史遗留。

### 要实现什么

`ReleaseManager.promote()`：读影子期证据，产出一次**judgement**（三态），
而不是直接改状态。晋升与拒绝晋升都要落审计。

### 必须先定的口径（每一条都可能把这道门禁做成假的）

1. **分歧率低 ≠ 候选更好。** 两个版本一起漏同一批问题时分歧率是 0。晋升
   条件不能只有"分歧率 ≤ 阈值"，至少要求候选在影子期**至少赢过基线一次**
   （存在基线漏、候选中的样本）。`shadow_samples` 表里有
   `primary_json` / `candidate_json`，够做这个判断。
2. **分母纪律（三态）。** `store.py` 现有代码里
   `disagreement_rate = disagreements / shadow_samples if shadow_samples else 0.0`
   ——样本为 0 时算出 0.0，**会直接满足"≤ 阈值"**。新方法必须返回
   `None`（样本不足，无从判断），不能返回"通过"。这与项目里
   `_empty_metrics` 的 CI 字段用 `None` 而非 `[0,0]`、
   `_significance_report` 用三态是同一条纪律。
3. **不要走 `save_deployment`。** 它会把
   `samples/errors/shadow_samples/disagreements` 全部重置为 0（`store.py:1233`
   附近），与 `stage_shadow` 防的是同一个坑。晋升写回要用增量 `UPDATE`。
4. **`skill_versions.active` 必须同步。** `store.py:1326` 那段已经做了，且
   注释解释了为什么内联而不是调 `activate_skill_version`（`self._lock`
   不可重入）。新路径**复用同一逻辑**，不要另写一份——两份实现迟早分叉，
   而分叉的表现是 `evolution.py` 下一轮读到的 baseline 与实际服务流量的
   版本不一致，这在报告上看不出来。

### 配套证明（与轨道 0 同构）

拒绝晋升的路径同样要有证明：构造一个"分歧率漂亮但其实候选和基线一起漏"
的场景，证明它被拦下。参照 `evoagent/rejection_proof.py` 的组织方式
（受控语料 + 确定性 reviewer + `claim_scope` 随报告落盘 + 证明失败时
脚本非零码退出）。

---

## 3. 轨道 I — ACE delta 机制（context collapse 缺口）

### 论文来源

[ACE: Agentic Context Engineering (arXiv:2510.04618)](https://arxiv.org/pdf/2510.04618)，
Stanford + SambaNova + UC Berkeley，ICLR 2026，
[官方实现](https://github.com/ace-agent/ace)。它指出上下文自适应的两个失效
模式：**brevity bias**（优化偏好简洁摘要，丢掉领域细节）与
**context collapse**（迭代重写逐步侵蚀已积累的细节）。

### 第二个在 EvoAgent 里真实存在，已查证

`evolution.py` 的 `_generate_candidate` 把整个 `base`（= 亲本提示词）交给
生成器，拿回一个**完整的** `candidate_prompt`。而 `base` 是逐代累积的：v5
的提示词里含着 v2、v3、v4 各自学到的规则。这就是迭代重写。

安全门禁挡不住。`safety_evaluate`（`evolution.py:463` 附近）：

```python
required = ("diff", "severity", "fix", "test", "json")
completeness = sum(token in lowered for token in required) / len(required)
```

**它检查的是"提示词还像不像一个 review 提示词"，不是"之前验证过的规则还
在不在"。** 一个候选可以删掉 v2/v3/v4 学到的三条规则，`completeness`
依然是 1.0，safety 门禁照过。

holdout 门禁只**部分**兜住，缺口恰在缝隙里：

- 纯粹丢失 → 分数下降 → 被拒。但拒绝理由写的是
  "a protected metric regressed"，**不会说"你删掉了三条已验证规则"**。
  诊断信息丢失，同一个根因会被反复重试。
- 更麻烦：候选丢了两条旧规则、加了一条更强的新规则，净分数**上升**。
  门禁放行，三代积累的知识悄悄少了两条，报告上完全看不出来。**这就是
  context collapse 的精确形态。**

### 要实现什么（只取 delta 机制，不抄三角色架构）

ACE 的 Generator/Reflector/Curator 三角色，项目里已有对应物（生成器 /
`_prior_attempts` 反思信号 / 门禁），再抄一遍就是换汤不换药。真正有价值
的是那一条：**增量 delta 更新，由确定性（非 LLM）逻辑合并**。

1. 提示词里已验证的规则**结构化成条目**，每条带来源 `run_id` 和它当初
   通过的门禁；
2. 生成器只能产出 delta（新增 / 修改某条），**不能整体重写**；
3. 合并由纯函数完成，不经 LLM；
4. 新增门禁：删除一条已验证条目必须是**显式**动作并给出理由，不能作为
   重写的副产品发生。

第 4 条与项目现有做法同源：`save_deployment` 会静默重置错误预算，所以
`stage_shadow` 默认拒绝而非覆盖。同一个模式——**静默丢失证据比丢失本身
更危险**。

### 建议的第一步（约 30 行，不阻塞轨道 G）

先写一个**失败测试**把缺口钉住：构造"删掉两条旧规则、加一条强新规则、
净分数上升"的候选，断言它**当前会被放行**。缺口一旦有测试钉住就不会在
后续改动中被遗忘，而它与轨道 G、轨道 H 都无依赖。

### 关于 TextGrad：建议**不**集成

[TextGrad](https://github.com/zou-group/textgrad)
（[Nature](https://www.nature.com/articles/s41586-025-08661-4)、
[arXiv:2406.07496](https://doi.org/10.48550/arxiv.2406.07496)）是 GEPA 的
前身，把 LLM 自然语言反馈当"梯度"沿计算图反向传播。

不集成的理由不是它不好，而是**项目里没有需要反向传播的计算图**。TextGrad
的价值在于把误差归因到复合系统的**中间**组件；而这里的进化对象是单个提示词
字符串，反馈到目标之间只有一跳。硬套只能得到"用 LLM 读反馈然后改提示词"，
即 `_generate_candidate` 已有的行为——多一层抽象、多一个依赖，换来同一个
结果。

可以引用的部分：TextGrad 的核心主张"自然语言反馈的信息量远大于标量分数"
**已经实现并落盘**了（`_prior_attempts` 把"这些根因过去被尝试过什么、门禁
怎么判的"喂回生成器）。引用一个已实现的机制是资产；引用一个没实现的机制
是负债。

---

## 4. 轨道 H — 让 `failure_cases` 有真实数据（**基建已完成，人工标注未做**）

> **2026-09-07：派生与导入两步 CLI 已实现**（`evoagent/feedback_import.py`、
> `scripts/import_replay_feedback.py`），194 条候选已落盘。下面那条硬约束
> 就是中间那道闸门，它是真的：未确认候选写库 0 条。见第 12 节。

这是解锁其余一切的前提：档案的逐样本分数、Pareto 选亲的真实信息、轨道 F
的口径验证全部卡在这。

现状（已查证）：全部 `.db` 里 `failure_cases` 非空的只有
`output/prompt-evolution-proof/prompt-evolution-proof.db` 的 32 条，来源是
`synthetic-controlled`。真实线上反馈 **0 条**。

最小可行路径：把 D6 replay 的真实误报/漏报按人工确认口径回流一小批。

**硬约束：必须人工确认。** 不能拿 replay 的自动判定当反馈——那会重演
"推断信号混进人工确认字段"这个已经被专门防过的错误（见 README 里
`merged_without_addressing` 那一段：人工反馈的四个类别意味着"人看过并确认
了"，推断结果写进同一字段，下游就再也分不出哪条有人背书）。

---

## 5. 轨道 F — 三层晋升脚本（**三个口径已全部定案并实现，见第 15 节**）

1. ~~`failure_case` 没有 diff~~ **已解决（2026-09-07）**：`import_confirmed`
   导入时把样本 diff 一并存进 `task_payloads`；
2. ~~`false_positive` 该进**负样本**（空 `expected_findings` → clean_accuracy
   侧），`missed_issue` 进正样本，而 `bad_fix` **没有对应的指标槽位**~~
   **已定案（2026-09-07 第二轮）**：`bad_fix` 显式拒绝提升并说明原因；
   `false_positive` **只在源样本本身干净时**才提升成负样本——这一条原文
   写漏了，见第 15 节；
3. ~~split 归属必须跟随仓库已有的一侧~~ **已实现**：`split_index` 查仓库
   已有的一侧，查不到则拒绝而不是猜，落在 holdout 一侧也拒绝。

第 3 条尤其要紧：`tests/test_rejection_proof.py` 里
`test_repositories_do_not_cross_the_split_boundary` 钉住的就是这个约束——
一个仓库同时出现在两边，holdout 就不再是"没见过的分布"。

---

## 6. 已推迟的实验

按"实验应该往后排、先补完闭环基建"这一原则推迟，不是取消：

- **D3 记忆消融** `scripts/run_memory_ablation.py`（`service.py` 的注释里
  已被引用，脚本尚未编写）：冻结只读快照、两个 tenant_id、用 Track E 的
  显著性报告判读。
- **31 条 severity 人工校准抽样的判者稳定性复跑**
  （`scripts/sample_severity_calibration.py`）：**只能报告 judge 稳定性，
  不能表述为人工校准。** 现有数据是一致率 0.4061、κ = −0.0019，足以证伪
  原标签，不足以充当新真值——κ≈0 区分不了"judge 对、正则是噪声"和"两边
  都是噪声"。未通过 κ≥0.6 且一致率≥0.85 的门禁前不得当 ground truth。

---

## 7. 文档债

- `datasets/README.md` §3.3 写"约 11:5 仓库"，实际是 15 仓库 **11:4**；
- L1 档缺口与 `rule_covered` 3/95 应记为局限；
- **holdout 里 0 条 high/critical 样本，`high_severity_recall` 那道门禁是
  空的。** 这条与轨道 0 直接相关：拒绝证明的语料里刻意钉住高危召回 1.0
  来隔离变量，但主数据集上这道门禁本身没有分母。

---

## 8. 已知 flake（未修，与上述工作无关）

`tests/test_advanced.py::AdvancedFeatureTests::test_async_multi_agent_review`
约 1/3 概率失败：`tearDown` 的 `os.unlink` 与异步 review 线程仍持有的
SQLite handle 竞争（`PermissionError: [WinError 32]`）。属异步生命周期
问题，建议单独处理，不要顺手在别的改动里带上。

---

## 9. 关于简历 bullet 的建议

**引用一篇没实现的论文是负债。** README 第一节整个结构（按证据等级分组
而非按功能分组）就是为了区分"跑过评测的"和"只写完了的"；往里塞背书会毁掉
这个结构的可信度，而这个结构本身是项目最强的部分之一。

值得写的形态是"论文用来定位自己代码里的一个真问题"，例如：

> 参照 ACE (ICLR 2026) 提出的 context collapse 失效模式，审计自身候选生成
> 路径，确认整体重写式生成 + 只校验通用 token 的 completeness 门禁无法保护
> 逐代积累的已验证规则；改为结构化条目 + 确定性合并的增量 delta 更新，并为
> "删除已验证条目"单独设门禁。

这与 README 里 GEPA/DGM 两处引用的用法一致——各自对应一个具体缺陷（标量
分数信息不足、单血统爬山），不是装饰。

**不建议**：把社交媒体上那张分类表（SkillOpt / R-Zero / MemEvolve /
SkillRL / Continual Harness / EnvHarness / Hyperagents / CORAL）搬过来
声称覆盖了 N 种进化对象。真实反馈 0 条的前提下，那是为没有证据的东西造
声势。评论区那句"不超过基础教科书水平的遗传算法，剩下就是想象力和纯灌水"
基本正确，本文档的判断建立在承认这句话的前提上。

**目前最有说服力的一点不是算法，是门禁**：自进化工作最普遍的失效是"在能
看见的数据上涨了就宣布进化成功"，而这个项目有一份可复现的记录，证明验证集
满分（0.7214 → 1.0）、受保护指标零退化的候选被 holdout 门禁拦在门外。

---

## 10. 建议的执行顺序（**已执行完 1、2、4，最新顺序见第 14 节**）

进度标记：1 ✅　2 ✅　3 ✅　4 基建 ✅ / 人工标注 ⬜　5 ⬜　6 ⬜。
原文保留，因为顺序的**依据**（末尾那段）仍然适用于第 14 节。

1. **轨道 I 第一步**（约 30 行失败测试，钉住 context collapse 缺口）——
   不阻塞任何东西，且缺口一旦被测试钉住就不会遗忘；
2. **轨道 G**（影子晋升判决 + 拒绝晋升证明）——闭环唯一还断着的一段，
   且不依赖真实数据就能做完并证明；
3. **轨道 I 剩余**（结构化条目 + delta 合并 + 删除门禁）；
4. **轨道 H**（真实反馈回流，需人工确认环节）；
5. **轨道 F**（三个口径问题解决之后）；
6. 推迟的实验与文档债。

顺序的依据：**一条断掉的路上的内容质量问题，优先级低于路本身**（所以 G 在
I 剩余部分之前）；而能用受控语料自证、不等真实数据的工作优先（所以 G、I
在 H 之前）。

---

## 11. 接手时必须遵守的既有约束

这些是项目里已经生效的纪律，不是建议：

- **`--clean-target` 必须保持为清洁/负样本采集的唯一显式开关**（默认 0/关闭）。
- **`datasets/real-pr-v1.jsonl`（95 条，权威）不得静默重新生成或覆盖。**
  重跑采集会得到不同的 PR ID，而现有 95 条被 `repos.yaml` 的分析按具体
  PR ID 引用。
- **重标注结果不得写回 `real-pr-v1.jsonl`**，合并需要人工确认环节。
- **任何昂贵的顺序 LLM/API 批处理必须逐条落盘**（append + `flush()` +
  `os.fsync()`）——"逐条落盘，不要一次失败全部重来"。
- **凭据不得回显或写入任何文件**：GitHub PAT 只作为单次 Bash 调用的
  内联环境变量前缀使用；`.env` 里的 `EVOAGENT_DEEPSEEK_API_KEY` 通过
  `set -a && . ./.env` 加载，不要打印。

---

## 12. 进度更新（2026-09-07）

第 10 节的建议顺序已执行到第 4 项。逐条对照：

| 顺序 | 轨道 | 状态 | 落点 |
|---|---|---|---|
| 1 | 轨道 I 第一步（钉住 collapse 缺口） | **完成** | `evoagent/prompt_rules.py`、`tests/test_prompt_rules.py`（19 用例） |
| 2 | 轨道 G（影子晋升判决） | **完成** | `ReleaseManager.evaluate_promotion`、`POST /v1/deployments/llm-review/promote`、`tests/test_shadow_promotion.py`（21 用例） |
| 3 | 轨道 I 剩余（delta 合并） | **完成** | `prompt_rules` 下半截（`make_entry` / `apply_delta` / `compose_prompt` / `entries_from_prompt`），`tests/test_prompt_rules.py` 增至 35 用例 |
| 4 | 轨道 H（真实反馈回流） | **候选已派生，标注工装已做，标注本身未做** | `evoagent/feedback_import.py`、`scripts/import_replay_feedback.py`、`tests/test_feedback_import.py`（47 用例） |
| 5 | 轨道 I 接线 + 轨道 F 提升层 | **完成（第二轮，见第 15 节）** | `_propose` 的 `gates` / `auto_propose` 的 delta 路径、`evoagent/case_promotion.py`、`scripts/promote_failure_cases.py` |

### 轨道 G 完成时改掉的一处设计错误

原计划第 2 节口径 1 写的是"分歧率低 ≠ 候选更好"，这一条正确并已实现
（`candidate_wins ≥ min_wins`）。但**实现时发现还有对称的一半没被写进
计划**：对称分歧率也不能当**否决**条件。

`len(primary ^ candidate) / len(union)` 分不出"候选多报一条"和"候选漏掉
基线报过的一条"。一个每次都多报一条真问题、一条都没漏的候选，对称分歧率
是 1.00，会被"分歧率 ≤ 0.20"当成退化拦下。风险在**漏**不在多。

这是跑测试时才暴露的——第一版实现确实在用对称分歧率否决。修法是给
`release_observations` 加 `candidate_only` / `primary_only` 两列，门禁改看
`loss_rate`，对称分歧率只作展示。**接手时若看到计划第 2 节只写了一半，
以代码和 README 为准。**

### 轨道 H 的现状要精确表述

对 D6 回放派生出 **194 条候选**（125 条 `unmatched_expected` / 69 条
`unmatched_finding`，覆盖 71 个样本，全部成功定位到 diff 片段），落在
`datasets/feedback-candidates-d6.json`。

**`failure_cases` 仍然是 0 条。** `import` 对这批未确认候选返回
`skipped_unconfirmed: 194`、写库 0 条——这是设计如此，不是没跑通。第 4 节
那条硬约束（必须人工确认）被实现成两步 CLI，中间那道闸门是真的。

派生阶段的两类候选刻意叫 `unmatched_expected` / `unmatched_finding`，
不叫 `missed_issue` / `false_positive`——后者是**确认之后**才能用的词。
要绕过 `HUMAN_CONFIRMED_CATEGORIES` 白名单不需要改它，只要在写库时把推断
结果写成一个字面合法的 category 就够了。

顺带解掉了第 5 节轨道 F 的口径问题 1：导入时把样本 diff 一并存进
`task_payloads`，所以这批反馈是**可提升的**。~~问题 2、3 仍未解决~~
——**已于第二轮全部定案并实现**，且发现口径 2 的原文写漏了一半，见第 15 节。

### 轨道 I 完成的是第一步，不是全部

第 3 节"建议的第一步"要求写一个失败测试钉住缺口。实际写的是**刻画测试**
（`ExistingGateBlindnessTests`）——断言缺口**当前确实存在**：一个删光三条
已验证规则的候选，`safety_evaluate` 的 completeness 仍是 1.0、safety 照过。
它现在是绿的；将来若把保留门禁接进 `_propose`，它会变红，那时该改的是
测试而不是门禁。这个方向比"写一个红着的失败测试"更适合长期留在套件里。

另外实现了 `retention_gate`（三态，基线无标记规则时返回 `None` 而不是
True）。~~但它尚未接进 `_propose` 的 `gates` 字典~~ ——**已于第二轮接线**：
按第 13 节 A 的建议做成纯报告项（进 `gates`，不进 `decision`，也不进
`rejection_proof.GATE_NAMES` 白名单），见第 15 节。`None` 两种收法都错：
当 True 则门禁在最常见情形下静默失效，当 False 则第一次进化被直接拦死。

ACE delta 机制的其余部分（生成器只产出 delta、确定性合并）**已于同日
补完**，见下。

### 轨道 I 剩余：delta 合并层

方向与上半截相反，两半都要留着：

- 上半截（`inventory` / `diff_rules` / `retention_gate`）是**事后清点**
  ——候选已经生成出来了，去数它丢了什么。能发现 collapse，但发现时那次
  LLM 调用已经花掉了。
- 下半截（`make_entry` / `apply_delta` / `compose_prompt`）是**事前
  构造**——让 LLM 决定"改什么"，让代码决定"改完之后集合是什么"。

走 delta 路径时，collapse 的那个形态"丢两条旧规则、加一条更强的新规则、
净分数上升"**无法表达**：一个只说 `add` 的 delta，合并结果必然仍含那两条
旧规则；要丢就得显式 `drop`，而 `drop` 必须给 reason。
`test_a_delta_can_not_express_a_whole_rewrite` 钉的就是这一条。

条目带来源 `run_id` 和它当初通过的门禁（计划第 3 节第 1 条的要求）。
刻意**不**记时间戳：这个结构会进提示词并被逐次 diff，一个每轮都变的字段
会让 diff 全是噪声。

实现层面三处"宁可报错也不猜"，理由都写在测试名里：非法 delta 整个拒绝、
不部分合并；`add` 一条已存在的规则被拒而不是静默覆盖/忽略；同一 rule_id
在一个 delta 里出现两次被拒（结果会取决于应用顺序）。

`entries_from_prompt` 负责把现存纯文本提示词抬举成条目——没有它 delta
路径永远起不了步。它把没有 `[focus-rule:]` 标记的条目（`auto_propose` 的
四条通用 directive）单独放进 `unstructured` 返回而不是丢掉：静默丢掉它们
就是又一次 collapse，只不过发生在我们自己的代码里。

~~**未接进 `auto_propose` 的候选生成路径**~~ ——**已于第二轮与
`retention_gate` 一起接线**（两条线是同一个决定，第 13 节 A 项已扩大范围
说明过），见第 15 节。

---

## 13. 候选加项分析（**A / B / C 已实施，D 只做了工装，见第 15 节**）

以下是对照当前代码重新评估出的加项，按"缺口是否已查证"分档。**未查证的
一律标明**，不要把它们和已查证的混在一起写进任何对外材料。

### A. ✅ 已做（2026-09-07 第二轮）：`retention_gate` 接进 `_propose`（缺口已查证）

> **范围已扩大**：delta 合并层（同日完成）同样处于"写好了没人调用"的状态。
> 两条线的接线是同一个决定，应该一起做：`retention_gate` 进 `_propose` 的
> `gates`，`apply_delta` 进 `auto_propose` 的候选生成路径。分开做会出现一段
> 时间里"清点已生效但候选仍是整体重写"，那时清点会对每个候选都报 False。

轨道 I 现在的状态是"函数写好了但没人调用"，这与它要修的问题同构——
`shadow_ready` 当初也是"判决产出了但没人消费"。留在这个状态越久越像
一个装饰性的模块。

要先解掉的口径问题只有一个，但它是硬的：**`None` 怎么处理。**

- 当 True → 现存所有 v1 提示词（都没有 `[focus-rule:]` 标记）都会静默
  通过，门禁在最常见的情形下等于不存在；
- 当 False → 第一次进化就被拦死，因为亲本必然是无标记的 v1；
- 建议：**进 `gates` 但不进 `decision`**，与 `significant` /
  `holdout_significant` 同一档（见 `_significance_report` 文档，它们是
  三态纯报告项，`decision` 完全不看）。先让"这个候选删了哪几条规则"出现
  在每次 run 的记录里，积累几轮真实数据之后再决定要不要升格成硬门禁。

同时必须改 `rejection_proof.GATE_NAMES`——那是个**白名单**，新增的报告项
不加进去才是对的（加进去会让 `_failing_gates` 把一个纯报告项算成门禁失败）。
这一点接手时容易做反。

### B. ✅ 已做（2026-09-07 第二轮，选项 3）：`bad_fix` 的指标槽位（缺口已查证，是轨道 F 的真正阻塞）

第 5 节口径 2 说 `bad_fix` "没有对应的指标槽位"。查证属实：
`_non_regressing` 的受保护指标是
`score / precision / recall / high_severity_recall`（+ 条件性的
`severity_accuracy` / `clean_accuracy`），全都是**检出**指标。一条
"发现对了但修复建议是错的"反馈，在现有评测体系里**无处落脚**——提升成
数据集样本之后，它对任何一个指标都没有影响。

这不是补一个字段的事，是"评测什么"的问题。三个选项，建议第三个：

1. 加一个 `fix_quality` 指标——需要修复建议的真值，而数据集里没有；
2. 把 `bad_fix` 反馈只用于提示词方向（现状，`directives` 里已有一条），
   不进数据集——那第 5 节口径 2 应该改写成"`bad_fix` 刻意不提升"；
3. **显式记为局限**：`promote` 脚本拒绝提升 `bad_fix`，并在报告里说明
   原因是"当前评测体系没有修复质量的真值"。

选 3 的理由与项目其它地方一致：一个提升了但影响不了任何指标的样本，会让
数据集看起来变大、门禁看起来更严，实际什么都没多测。

### C. ✅ 已做（2026-09-07 第二轮）：holdout 的 `high_severity_recall` 空分母（第 7 节文档债，但比"文档债"严重）

第 7 节把它归为文档债，**这个归类偏轻**。holdout 里 0 条 high/critical
样本意味着 `_non_regressing` 里那个受保护指标在 holdout 上恒等于
0.0 vs 0.0 —— 恒不退化，恒通过。**这是一道空门禁**，与轨道 I 的
`completeness`、轨道 G 的"低分歧率当通过条件"是同一类错误：报告上看着有
四道受保护指标，实际只有三道在工作。

建议至少做到：`_non_regressing` 对分母为 0 的指标返回 `None` 并列进一个
`unmeasurable` 清单（`evaluation_v2._unmeasurable` 已有现成实现和纪律，
`tests/test_gate_transparency.py` 钉着它）。**不改判定方向**，只是让报告
分得出"没退化"和"测不出来"。

### D. ✅ 已做（2026-09-07 第三轮）：轨道 H 的第二步走完

> **修正**："不需要新代码"这句不准确。确实加了工装：`worksheet` /
> `apply-worksheet` 两个子命令，把 30 条候选渲染成 label 列留空的 Markdown
> 清单（`output/feedback-labelling/worksheet-expected.md` 已生成），填好后
> 写回候选文件。让人去手改那个 194 条的嵌套 JSON 是在制造填错位置的机会。
> **标注本身仍未做，且刻意不由程序代劳**，理由见第 15 节。

194 条候选已经躺在那里，人工标注是纯人力活。**建议先只标一小批**
（比如按 `alert_labelling.sample_alerts` 的确定性种子抽 30 条），把
`failure_cases` 从 0 变成非 0，让档案的逐样本分数、Pareto 选亲第一次有
真实输入。在此之前轨道 F 做完也验证不了。

盲标纪律是不对称的，已实现在 `blind()` 里：判"是不是误报"必须盲，判
"该不该报"不能盲。标注前请读 `feedback_import.py` 的模块文档。

### E. 不建议做：把 ACE 的三角色架构抄进来

第 3 节已经给过理由（Generator/Reflector/Curator 在项目里都有对应物），
这里只补一条实施层面的：现在 `_generate_candidate` 有一个 TypeError 退化
分支来兼容只接受两参数的第三方生成器。再加一层角色分工会让这个兼容面继续
扩大，而它已经是代码里比较脆的一处。

### F. 不建议做：TextGrad 集成

第 3 节的判断（项目里没有需要反向传播的计算图）复查后仍然成立，无新增
信息。

### G. ⬜ 结论：问题问错了，真正的前置是第 16.6 节的消费账本缺口（见第 16.7 节）

档案的逐样本 Pareto 选亲**从未在非空数据上跑过**（`versions_evaluated`
为 0）。D 做完之后，第一件事应该是看 Pareto 前沿是不是退化成"只有一个
版本"——如果每个候选在所有样本上都被 active 版本支配，前沿就只有一个点，
`pareto` 策略等价于 `active`，而报告上看不出这一点。

**这条是猜测，未查证。** 写进计划是为了提醒 D 完成后去看，不是结论。

### H. 明确不建议：那张进化对象分类表

第 9 节的判断不变，且现在有了更具体的理由：`failure_cases` 依然是 0 条。
在真实反馈 0 条的前提下声称覆盖 N 种进化对象，是为没有证据的东西造声势。

---

## 14. 修订后的建议执行顺序

进度标记：1 ✅　2 ✅　3 工装 ✅ / 标注 ✅（**模型标注，见第 16 节**）　4 ✅
　5 ⬜（已跑但未跑完，见第 16.7 节）　6 部分 ✅。

1. ✅ **C**（holdout 空门禁三态化）——它是一道**当前正在假装工作**的门禁，
   优先级高于任何新功能；
2. ✅ **A**（`retention_gate` 接进 `gates`，纯报告档）——让轨道 I 不停留在
   "写好了没人调用"；
3. ✅ **D**（标一小批候选，`failure_cases` 从 0 变非 0）——解锁其余一切。
   工装见第 15 节；标注由**模型**完成（60 条，带 `[model-labelled]` 前缀、
   只写 scratch 副本），`failure_cases` 已从 0 变 **20**，见第 16 节；
4. ✅ **B**（`bad_fix` 口径定案）→ 轨道 F 已实现；
5. ⬜ **G**（Pareto 前沿在真实数据下的行为，先查证再说）——依赖 3。
   已解除阻塞并实际跑完一轮真实评测：**G 问错了**，单版本档案的前沿必然
   是单点；真正拦住它的是第 16.6 节的消费账本缺口，不是缺数据。
   下一轮该做的是修那个缺口，见第 16.7 节；
6. ~~轨道 I 剩余（delta 合并）~~ ✅（2026-09-07）、推迟的实验、其余文档债
   （`datasets/README.md` 那两条 ✅，见第 16 节开头）。

顺序依据与第 10 节一致，并补一条：**一道假装在工作的门禁，比一个缺失的
功能更危险**——前者会让人以为已经被保护了。所以 C 排在最前。

---

## 15. 第二轮进度（2026-09-07）

第 14 节的 1、2、4 已完成，3 完成了工装那一半。逐条对照：

| 项 | 内容 | 状态 | 落点 |
|---|---|---|---|
| C | holdout 空门禁三态化 | **完成** | `_non_regression_report` 的 `unmeasurable`、`_propose` 的 `non_regression_unmeasurable`、`tests/test_gate_transparency.py`（24 用例） |
| A | 轨道 I 接线 | **完成** | `retention_gate` → `_propose` 的 `gates`（纯报告项）、`apply_delta` → `auto_propose`、`tests/test_prompt_rules.py`（41 用例） |
| B + 轨道 F | 三个口径定案 + 提升层 | **完成** | `evoagent/case_promotion.py`、`scripts/promote_failure_cases.py`、`tests/test_case_promotion.py`（25 用例） |
| D | 人工标注 | **工装完成，标注未做** | `worksheet` / `apply-worksheet` 子命令、`output/feedback-labelling/worksheet-expected.md`（30 条）、`tests/test_feedback_import.py`（47 用例） |

### C 的做法：只加清单，不动判定方向

`_non_regressing` 拆成 `_protected_metrics` / `_non_regression_report` /
`_non_regressing`（后者是 `report["passed"]` 的别名，判定方向一字未改）。
新增的 `unmeasurable` 列出"受保护但 baseline 侧为 None"的指标——即
**通过只是因为没什么可比**。holdout 里 0 条 high/critical 样本时，
`high_severity_recall` 就落在这个清单里。

顺带把拒绝理由从"a protected metric regressed"改成点名具体指标：不点名
会让同一个根因被反复重试（与 `retention_gate` 的 reason 点名删了哪几条
规则同一个理由）。

### A 的做法：进 `gates`，不进 `decision`，不进 `GATE_NAMES`

`None` 两种收法都是错的（当 True 则门禁在最常见情形下静默失效，当 False
则第一次进化被直接拦死），所以按第 13 节 A 的建议做成纯报告项。
`rejection_proof.GATE_NAMES` 是**白名单**，刻意不加——加进去会让
`_failing_gates` 把一个纯报告项算成门禁失败。
`test_the_report_only_item_is_not_counted_as_a_failing_gate` 钉的就是这个。

### 轨道 F：第 5 节口径 2 原文写漏了一半

原文"`false_positive` 该进负样本（空 `expected_findings` →
clean_accuracy 侧）"**只在源样本本身干净时成立**。

`real-pr-v1.jsonl` 的每条样本都是反转 fix PR 得来的，diff 里含着一个种子
缺陷。拿这样一个 diff 配上 `expected_findings=[]` 写进评测集，断言的是
"这里不该报任何东西"——而这是假的：那个种子缺陷真在里面，reviewer 报它是
对的。这个样本会把"报对了真缺陷"记成 clean_accuracy 上的一次失败，方向
正好教反。这与 `feedback_import` 拒绝把"标注外但确认有效"当误报是同一个
错误的另一副面孔。

所以只有源样本 `expected_findings` 为空（来自 `real-pr-clean-v1.jsonl`
那批负样本）时才提升成 clean 样本，否则拒绝并写清理由。
`test_a_source_case_carrying_a_seed_defect_is_refused` 钉住这一条。
**接手时若看到第 5 节口径 2 只写了"该进负样本"，以代码和本节为准。**

`bad_fix` 按第 13 节 B 的选项 3 处理：拒绝提升，理由是"当前评测体系没有
修复质量的真值"，且这条理由原样进报告——被静默丢掉的反馈和被评估过后
判定不该提升的反馈，在报告上必须分得开。

另外提升的目标是 store 的 `evaluation_cases` 表，**不是**
`datasets/*.jsonl`。这一点最容易搞反：jsonl 是权威输入语料（第 11 节
禁止静默重新生成），而 `_propose` 每轮真正打分用的是 `evaluation_cases`。

### D 只做了工装，标注本身没做，这是刻意的

`worksheet` 子命令按固定种子确定性抽 30 条（默认 `unmatched_expected`
一类），渲染成带 diff 片段、`label:` 列留空的 Markdown 清单；
`apply-worksheet` 把填好的清单写回候选文件。不要求人去手改那个 194 条的
嵌套 JSON——在嵌套 JSON 里填 label 最容易填错位置，而填错位置的表现是
一条判定被挂到别人身上。

**没有由程序把这 30 条标掉，是因为那会让整道闸门失效。** 一条程序写出来
的 label 是推断结论，而两步 CLI 中间那道闸门的全部意义就是推断结论不得进
`failure_cases`。填了 label 列，`HUMAN_CONFIRMED_CATEGORIES` 依然会放行，
因为它检查的是 category 字面是否合法，而不是背后的数据是不是真的有人看过。
所以 `failure_cases` 现在仍是 **0 条**，这个数字是诚实的，而一个由程序
填出来的非 0 才是有害的。

清单渲染时保持了 `blind()` 的不对称纪律：`unmatched_finding` 一侧不展示
`cwe` / `defect_class` / `label_provenance` / `fix_pr_url`。注意真正的
剥离必须在派生时用 `--blind` 做——清单是从候选文件渲染的，候选文件里若
还带着线索，人只要打开那个文件就看见了。

### 仍然阻塞在人工标注上的东西

> **第三轮已解除这道阻塞**（由模型标注，见第 16 节）。以下三条的**当前**
> 状态：G 仍未得出结论（第 16.7 节）；提升层已在真实反馈上跑过，20 条进
> `evaluation_cases`，不再是空计划；`versions_evaluated` 仍为 0，原因见
> 第 16.5 / 16.6 节。本小节保留原文以便对照。

- 第 13 节 G（Pareto 前沿在真实数据下是否退化成单点）；
- 轨道 F 的提升层现在跑出来**必然是空计划**（0 条反馈可提升），它只有
  单测覆盖，证明的是"口径已定案且被钉住"，不是"在真实反馈上跑过"；
- 档案的逐样本分数、`versions_evaluated` 仍为 0。

### 未做的文档债（第 7 节仍然适用）

- ~~`datasets/README.md` §3.3 写"约 11:5 仓库"，实际是 15 仓库 **11:4**~~
  → **已补**，见 `datasets/README.md` §3.3 的"设计目标 vs 实际落地"对照表；
- ~~L1 档缺口与 `rule_covered` 3/95 应记为局限~~
  → **已补**，见 `datasets/README.md` 新增的 §3.4「已知局限」；
- 第 8 节那个 flake 未修。

## 16. 第三轮：模型标注 + 第一次真实进化轮（2026-09-07）

这一节记录三件事：这批 label 是谁标的、标出来的**负面结果**、以及第一次
真实跑进化轮时暴露的两个缺陷。

### 16.1 标注者是模型，不是人 —— 以及为什么这不违反第 15.4 节的闸门

第 15 节写着"没有由程序把这 30 条标掉，是因为那会让整道闸门失效"。用户随后
明确要求由模型来标（"我要求你帮我标注"），这是用户的决定。落地时加了两道
约束，使得模型推断出来的判定**永远无法冒充人工确认的判定**：

1. **每条 note 以 `[model-labelled]` 开头。** 这个前缀随 note 一起进
   `failure_cases`，所以整批数据任何时候都能被检索出来、整批删掉。
2. **只写 scratch 副本，不写 `datasets/` 也不写主库。** 落点是
   `output/feedback-labelling/` 下的
   `candidates-d6-model-labelled.json` 与 `model-labelled.db`。
   `datasets/feedback-candidates-d6.json` 与主库一个字节都没动。

第 15.4 节指出的技术事实仍然成立且未被修复：`HUMAN_CONFIRMED_CATEGORIES`
检查的是 category 字面是否合法，不是背后有没有人真的看过。**绕过它不需要
改白名单，只需要在插入时写一个字面合法的 category 字符串。** 所以这里的
隔离靠的是 provenance 前缀 + 存储位置，而不是靠那道白名单。

标注规模：expected 侧 30 条（should-have-caught 20 / not-expected 8 /
unlabelled 2），finding 侧 30 条（valid 28 / valid-but-noise 1 /
unlabelled 1）。

### 16.2 负面结果：标误报侧**填不了** `clean_accuracy` 的空分母

第 1 步原本的目的是"标 `unmatched_finding` 侧，把 `clean_samples: 0` 这个
空分母填上"。**这个目的没达成，而且是原理性的达不成，不是标注做得不够。**

finding 侧 30 条里 `invalid` = **0**。

原因：`real-pr-v1.jsonl` 的每条样本都是反转真实 fix PR 得来的，每条 diff 的
`+` 侧都埋着一个种子缺陷。模型对着一个确实有缺陷的 diff 报警，绝大多数
时候是对的。所以这个语料在结构上**几乎产不出误报**——想靠标它来攒负样本，
方向就错了。

负样本只能来自 `datasets/real-pr-clean-v1.jsonl`（78 条干净样本）。这与第
15 节「轨道 F 口径 2」是同一条约束的两个面：**只有源样本本身干净，才能提升
成 clean 样本**；反过来，只有干净源样本上的告警，才是真误报。

结论：`clean_accuracy` 的分母要靠 clean 语料入库来填，不在标注工作量上。

### 16.3 一条会被误读的数据集性质：`expected_findings` 是按 hunk 行自动派生的

8 条 `not-expected` 全部源于这一个机制。最干净的实例是
`encode__httpx-pr-3042`：它的**唯一** expected finding 是一行新增的
`# pragma: no cover`，而同一个 PR 里删掉 cookies 弃用告警、删掉文档段这些
实质改动**没有**被标进去。

所以 `unmatched_expected` **不等于**"reviewer 本该报却漏了"。纯字符串、
注释、import、覆盖率标记都会进 expected。用它直接算召回会低估。
（已同步写进 `datasets/README.md` §3.4。）

另外核实（不是假设）了 diff 方向约定：`diff` 的 `+` 侧是缺陷侧，
`human_patch` 是真实修复。在 `aio-libs__aiohttp-pr-12796` 上逐字段对比过。
60 条 label 全都压在这个约定上，所以先验证再标。

### 16.4 跨侧一致性是一条真实的纪律，不是形式检查

`dd1308777771bced`（expected 侧）与 `d37c17b820f3565c`（finding 侧）是
aiohttp `web_ws.py:290` **同一处代码**。我起初把前者标成 `unlabelled`、
后者标成 `valid` —— 而"接受这条告警有效"就意味着"这处削弱是真的"，那前者
就不可能是判不了。改判前者为 `should-have-caught`。

同类的自查还改掉一条：`0563154e77cdcef5` 原判 `not-expected`（理由是
`Mapping`→`MutableMapping` 属设计取舍），读 `fix_pr_title`（"Fix
`extensions` type annotation."）与 `human_patch` 后确认这正是该 PR 点名修
的那处缺陷，改判 `should-have-caught`。

### 16.5 第一次真实进化轮暴露的两个缺陷

闭环第一次在真实数据上端到端跑通：replay → 派生候选 → 标注 →
`apply-worksheet` → `check` → `import`（20 条进 `failure_cases`）→
`promote`（20 条进 `evaluation_cases`）→ `auto_propose`。

**缺陷 1：`JsonChatClient` 把"token 预算被推理吃完"报成"模型返回了非法
JSON"。**

`deepseek-v4-flash` 是推理模型，`max_tokens` 同时封顶 reasoning + content。
`RootCauseEvolutionGenerator` 默认 `token_budget=6000` 被推理耗尽，
`content` 返回空串、`finish_reason` 为 `length`，而 `complete_json` 直接
`json.loads("")`，报出：

    deepseek JSON request failed: Expecting value: line 1 column 1 (char 0)

照着这条消息去查 JSON 解析永远查不到病根。已在 `evoagent/llm.py` 加空
content 检查，把 `finish_reason` / `completion_tokens` / `reasoning_tokens`
/ `max_tokens` 一并报出来，并提示这是预算问题。已在压小 `max_tokens` 的
实探上复现确认（`finish_reason=length`、`reasoning_tokens=64/64`、
`content=''`）。

**缺陷 2：安全门禁的 `FORBIDDEN` 用裸子串，方向是反的。**

第一个真实候选被 safety 门禁拒了，命中的是裸子串 `"bypass"`，出处是候选
提示词里这条规则：

    ... so reintroduced algorithms and bypassed timeout settings are visible.

一条**要求 reviewer 去发现被绕过的超时配置**的规则，被当成了绕过审查的
注入指令。而 `bypass` 是安全评审的核心词汇——裸子串等于让安全门禁永久
拒绝一切讨论绕过的候选，这恰恰是安全 reviewer 提示词最该讨论的东西。

这与语料里 `d37c17b820f3565c` 是**同一个缺陷类**：子串匹配没有 token
边界。那一处让非法 token（`notupgrade` / `upgraded`）通过，这一处让合法
文本被拒。已把 `FORBIDDEN` 改成带动词宾语的短语（`bypass safety` /
`bypass review` / `bypass validation` / ...），取"指令"这一义项。
`tests/test_prompt_rules.py::ForbiddenTokenBoundaryTests` 同时钉住两个
方向：真实被拒那句话必须通过，且真正的注入指令仍须被拦。

**顺带修掉的可诊断性问题**：`safety_evaluate` 原来只报
`safety_passed: False`，三个失败原因（空 / 超长 / 命中黑名单）在报告上
完全无法区分。第一个候选被拒时报告写着 `completeness: 1.0,
missing_terms: []`——看上去一切正常却判了拒绝，只能回读源码才能诊断。
现在加了 `forbidden_hits` / `empty_prompt` / `too_long` /
`prompt_length`。这与第 15 节 C「不点名会让同一个根因被反复重试」是同一
条纪律。

### 16.6 `_select_cases` 的消费账本会因无关失败烧掉反馈

修完 `bypass` 后重跑，`auto_propose` 返回 `deferred`（"no new supported
learning signal"），`triage.already_attempted` = **20**。

原因：上一轮那个被 `bypass` 误拒的候选，已经给全部 20 条 root cause 记了
一次 attempt。而 `_select_cases` 的第 2 道过滤按 `failure_case_id`
**无条件**排除已尝试过的 case。于是 20 条反馈被一个与它们本身无关的
门禁 bug 一次性烧掉。

这道过滤本身是必要的（没有它循环会停在原地反复生成同一个候选，第 15 节
已论证）。但它现在不区分"这条反馈驱动的修改被评估后判定不够好"和"这一轮
因为一个无关缺陷整体失败了"。**这是一个真实的设计缺口，尚未修**——本轮
只是在 scratch 库上清掉 `evolution_attempts` / `evolution_runs` /
`skill_versions` 后重跑（备份在 `model-labelled.before-reset.db`）。

修法留待下一轮，两个候选方向：按 `run_id` 的失败原因分类，只有进入过真实
评测的 attempt 才计入消费账本；或给 attempt 加一个"是否可重试"的字段。

### 16.7 第 13 节 G 的结论：**问题问错了，前沿在只有一个版本时无法退化**

第三次跑（清账本后）走完了完整门禁链，这是闭环第一次真的产生评测数字：

| 指标 | 基线 | 候选 | |
|---|---|---|---|
| score | 0.5937 | **0.6049** | ↑ |
| precision | 0.4286 | 0.4444 | ↑ |
| recall | 0.6 | **0.8** | ↑ |
| f1 | 0.5 | **0.5714** | ↑ |
| severity_accuracy | **1.0** | 0.75 | ↓ **回退** |
| high_severity_recall | null | null | 空分母 |
| clean_accuracy | null | null | 空分母（validation `clean_cases: 0`）|

> **这张表的分数已作废**：第 17 节导入干净语料后
> `validation_dataset_fingerprint` 变了，评测集不再是同一套，导入前后不可
> 直接比较，基线需重跑。表里的**结论**仍然成立，而且正是它说明了为什么
> 误报侧必须有分母：候选靠多报换 recall，最后只被 holdout precision 拦住。
> `clean_accuracy` 那两个 null 就是第 17 节要修的病象本身。

holdout（2 条）：precision 0.5 → **0.25**、score 0.5833 → **0.41**，回退。

判决 `rejected`，理由点名了具体指标：

    a protected validation metric regressed (severity_accuracy);
    a protected holdout metric regressed (precision, score)

**这是一次门禁在真实数据上正确工作的记录**：候选把 recall 从 0.6 拉到 0.8，
如果只看 score / f1 它是"变好了"，但严重度判定从 1.0 掉到 0.75、holdout
precision 腰斩——多报了 9 条（基线 7 条）里混进了错的。第 15 节 C 那条
"拒绝理由必须点名具体指标"在这里第一次有了实战输出。

**关于 G 本身：`frontier_size` = 1，但这个 1 不构成对 G 的回答。**

档案里只有 **1 个**被评测过的版本（`versions: 1`,
`versions_evaluated: 1`），`frontier_weights` 是 `{"1": 5}`——它在全部 5 条
样本上"胜出"，因为没有竞争者。**一个版本的前沿必然是单点，这是平凡结论，
不是退化。** G 问的"每个候选是否在所有样本上都被 active 支配、导致 pareto
等价于 active"，需要**至少两个被评测过的版本**才能观察，而这需要至少两轮
候选都进到评测阶段。

本轮之所以只有一个：候选被拒 → 不激活（`active_version: null`）；而要跑第
二轮，20 条反馈已被本轮全部计入消费账本（第 16.6 节那个缺口），
`_select_cases` 会再次返回空。**所以 G 的真正前置条件不是"人工标注"（第
15 节的判断），而是第 16.6 节那个消费账本缺口**——不修它，档案里永远只会
积累一个评测过的版本，Pareto 选亲的代码路径也就永远得不到真实检验。

这是本轮最值得记的一条：G 被当成"缺数据"挂了两轮，实际拦住它的是一个
记账缺陷。

**另外，`frontier_size: 0` 有两个完全不同的含义，报告上分不开。** 前两次跑
（safety 拒 / deferred）与本次跑之前，`pareto_frontier` 都是 `[]`、
`versions_evaluated` 都是 0——"从来没跑过评测"和"跑过但前沿为空"在
`archive_report` 里长得一样。`archive.pareto_frontier` 在没有逐样本数据时
刻意返回 `[]` 而不是"所有版本"，这个选择是对的（不虚报），但配上
`frontier_size: 0` 就少了一层区分。`versions_evaluated` 已经在同一份报告里，
读的时候必须一起看。
---

## 17. 干净语料入库：给误报侧补上分母（2026-09-07）

### 17.1 症状：两个门禁同时静默失效

`_score` 里误报侧的权重挂在一个条件上（`evolution.py:322`）：

```python
if clean_total:
    ...  # 0.20 权重的 clean_accuracy 项
```

`_protected_metrics` 里的回归保护挂在另一个（`evolution.py:1117`）：

```python
if baseline.get("clean_cases", 0):
    ...  # clean_accuracy 不得回退
```

`clean_total` 为 0 时，**这两条一起消失**，而 `score` / `precision` /
`recall` 照常打印，报告上看不出任何异常。门禁于是只从「漏报」一个方向拉
候选：多报一个 finding 不受任何惩罚，少报一个立刻扣分。飞轮会持续朝
「多报」漂。

**一个看起来在工作的门禁，比一个缺失的门禁更危险**——这是本项目反复出现
的同一种形态。

### 17.2 根因不是「没有语料」，是「取样够不到」

第一反应是「库里没有干净样本」。查了一下不是：`evaluation_cases` 的 id
24、25 本来就是干净样本。真正的原因在取样口径——
`list_evaluation_cases` 是 `ORDER BY id LIMIT ?`，而干净语料是后来补进去
的，id 必然更大，**永远排在缺陷样本后面**。实测 `LIMIT 5` 返回 id 1–5，
全是缺陷样本。

这直接决定了修法：**只写一个 loader 什么都修不了**。78 条新语料落在 id 28
以后，照样一条都选不中。所以必须是两件事——分层取样 + 语料导入。

### 17.3 改动

| 文件 | 改动 |
| --- | --- |
| `evoagent/store.py` | `select_evaluation_cases` 落实分层配额；新增类常量 `max_clean_share = 0.5`；删掉一段永不可达的防御代码 |
| `evoagent/evolution.py` | `status()` 与 `_propose()` 两处调用点改走分层口径（**这才是本次改动的全部价值**） |
| `scripts/import_clean_corpus.py` | 新增，把 `datasets/real-pr-clean-v1.jsonl` 导入 `evaluation_cases` |
| `tests/test_clean_corpus.py` | 新增，17 个用例 / 33 个子用例 |
| `tests/test_import_clean_corpus.py` | 新增，7 个用例 |

### 17.4 分层取样的三条约束

**1. 必须确定性，不能随机。** `_propose` 会把
`validation_dataset_fingerprint` 落盘。取样一旦带随机性，同一个库在两轮
之间会算出不同指纹，指纹就失去了它唯一的含义——「这两轮跑的是同一套评测
集」。所以是 `positive[:quota] + clean[:quota]` 再按 id 排序，不是抽样。

**2. `limit` 是预算，不是建议值。** `limit=1` 时两层各留 1 条必然超预算；
超限比少一层更糟，这种情形退回原口径。

**3. 份额上限 0.5，因为库内比例反映的是「哪种样本便宜」。** 干净 PR 批量
抓取拿到 78 条，人工确认过的缺陷样本只有 20 条。纯按比例取样时
`limit=20` 会取出 4 缺陷 + 15 干净，recall 的步长变成 0.25——等于用「补上
误报侧的分母」换掉了漏报侧的分母。

另有一条边界：**预算装得下整张表时不做任何取舍，全给。** 少了这一支，
调用方明明请求全集却拿到子集，等于对数据集规模说谎。

### 17.5 我引入的两个缺陷（都不是被测试抓到的）

**（1）份额上限按预算算，在缺陷层存量不足时失效。**
第一次真实导入后，`validation@500` 取出 88 条，其中 **65 条干净（74%）**
——正是这个上限本该拦住的形态。原因是配额按 `limit * share` 算，`limit`
一旦超过缺陷层存量，上限就变成一个够不着的数字。修法是把上限改成按**实际
取到的缺陷条数**算：

```python
clean_quota = min(clean_quota, positive_quota)
```

并排验算了两个公式：旧式 `limit=500` → 80% 干净；新式 → 50%。
**我自己的测试没抓到它**，因为用例只跑到 `limit=40`。补了
`test_share_cap_holds_when_the_defect_stratum_runs_short`。

**（2）打断了 `tests/test_rejection_proof.py`（6 个失败）。**
症状是 `gates["evaluation_success"] is None`、markdown 里找不到 `PASS`、
理由是「candidate saved but the holdout dataset is smaller than the
activation minimum」。`rejection_proof` 按 `max_cases=len(cases)` 请求全部
20 条 holdout，我的份额上限只给了 12 条，`holdout_dataset_ready` 于是失败。
修法就是 17.4 末尾那条「预算装得下整张表就全给」。补了
`test_a_budget_covering_the_whole_table_returns_everything`。

这个修法又让另一条用例的前提失效：
`test_sample_shrinks_honestly_when_a_stratum_runs_out` 原本用
`limit=98` 打 98 条存量，现在走的是全表分支。改成 `limit=90`，并在
docstring 里写清 limit 必须**严格小于**总存量。

**两个缺陷都是跑出来的，不是测出来的。** 测量数字写进了对应用例的
docstring，这样下次有人想「简化」这两条分支时能读到原因。

### 17.6 导入结果与前后对比

```
inserted=78  skipped_duplicate=0  rejected=0
by_split={'validation': 63, 'holdout': 15}
```

78 条全部通过 `validate_case`，无一被拒。

导入前后，在引擎真实使用的 `max_cases=20` 下（`status()` 和 `_propose()`
现在走的是同一条口径）：

| 切分 | 导入前 | 导入后 |
| --- | --- | --- |
| validation | 18 缺陷 + **0 干净** | 10 缺陷 + **10 干净** |
| holdout | 5 缺陷 + **0 干净** | 1 缺陷 + **16 干净** |

（库内存量：导入前 validation 23 缺陷 / 2 干净，holdout 1 缺陷 / 1 干净。）

两侧的 `clean_accuracy` 现在都有分母了。

### 17.7 用法

```bash
python scripts/import_clean_corpus.py --db <path> --dry-run
python scripts/import_clean_corpus.py --db <path>
```

loader 只写库，**不碰 `datasets/` 下的任何文件**。它拒收三类行：带
`expected_findings` 的（必须走有人工闸门的那条路）、split 不认识的、
`validate_case` 打不出分的。重跑幂等，且**幂等体现在报告上**——第二次跑报
`inserted=0 / skipped_duplicate=78`，而不是照样报 78 次插入。导入结束会
直接打印分层取样后的实际 `clean_denominator`：「插入了 N 条」不是证据，
插进去和选得中是两回事。

### 17.8 两条必须记住的限制

**1. 干净语料的标签是「缺陷缺席」，是代理信号，不是「已验证正确」。**
语料自己的 `source.note` 就是这么写的：180 天观察窗内未见 bugfix 型后续
提交。所以 `clean_accuracy` 只能当误报压力的近似量，不能当正确性证明。

**2. 第 16.7 节的分数已作废，基线必须重跑。** validation 集的构成变了，
`validation_dataset_fingerprint` 必然随之改变，导入前后的分数不可直接
比较。那张表里两个 `clean_accuracy: null` 的格子，正是本节所修的症状。

测试总数：**849 passed, 39 subtests**（改动前 824）。

---

## 18. 已知局限与下一步（截至 2026-09-07）

### 18.1 三条回路仍然没有闭合

- **回路 A（拒绝 → `_prior_attempts`）** 仍被第 16.6 节那个消费账本缺口
  卡住：`_select_cases` 会因为**与反馈无关的失败**烧掉反馈额度，20 条反馈
  被一轮全部计入消费，第二轮直接返回空。这条是回路 A 与第 13 节 G 的共同
  前置条件。
  两个候选修法（**等设计决策，我没有单方面开工**）：
  1. 按失败原因分类，只有真正跑到评测阶段的尝试才计入消费——判据已经存在，
     就是 `gates.evaluation_success`，按 `run_id` 关联。**我倾向这条。**
  2. 给反馈加一个 `retriable` 字段。
- **回路 B（激活 → 生产 → 新反馈）**：至今没有任何候选通过门禁，回路 B
  在事实上还不存在。
- **回路 C（新版本 → 重放）**：依赖 B。

### 18.2 语料与门禁

- **holdout 只有 1 条缺陷样本**（`holdout-security-shell-execution`，
  source 为 `builtin`）。所以第 17.6 节那个「1 缺陷 + 16 干净」是全表分支
  的诚实输出，不是取样缺陷——但它意味着 holdout 上的 recall 只有一个步长，
  实际不可用。**补 holdout 缺陷样本是下一步语料工作的第一优先级。**
- `HUMAN_CONFIRMED_CATEGORIES` 的绕过口仍在。
- 语料没有按难度分层，也没有 L1 档。
- **还没有任何一轮候选是在「误报侧有分母」的条件下跑出来的。** 第 17 节
  只保证了仪表有读数，读数本身要等下一轮才拿得到。

### 18.3 挂起项

- D3 记忆消融实验（按既定安排后置）。
- 严重度校准：agreement 0.4061、κ −0.0019，门槛是 κ≥0.6 / agreement≥0.85。
  这个结果只能作为**评审模型不稳定**的证据报告，不能当校准结论。
- `test_async_multi_agent_review` 偶发失败（`PermissionError [WinError 32]`，
  约 1/3 概率）。本轮未复现。

---

## 19. 消费账本与 holdout 分母（2026-09-08）

第 18.1 的两个候选修法采纳**方案 1**；第 18.2 的 holdout 缺口一并处理。

### 19.1 消费账本：判据不是"跑没跑评测"

新增 `EvolutionEngine._verdict_is_about_the_feedback`，用现成的
`gates.evaluation_success` 三态判断这一轮该不该记消费——**没有加 schema
字段**：

- **不是 None** —— 候选跑完了基线与候选的全量回放。无论 activated 还是
  rejected，门禁都在回答"照这批反馈改出来的提示词好不好"。该消费。
- **是 None** —— 压根没到评测。safety 拒了、评测集不够大、没配 provider、
  候选与 active 逐字相同。这些失败**与反馈内容无关**。不该消费。

`None` 在 `evolution.py:592` 初始化，只在 `:637` 真正跑
`RegressionEvaluator` 的那一支被赋成 bool，所以它本来就是"这轮没进过评测"
的精确定义。

**但判据的措辞很重要：不是"跑没跑评测"，是"有没有人对着这批反馈做出
判断"。** 两个 `deferred` 调用点（生成器认为无需改动、delta 合并没找到
可支持的信号）同样没跑评测，却**必须**消费——它们是对着这批反馈下的
判决，不记的话下一轮会重跑同一次 LLM 调用得到同一个结论。所以这两处的
记账保持无条件，只有 `_propose` 那条路上的前置中止走新判据。

不写账本不丢审计线索：这些轮次都留下了 `evolution_runs` 记录，中止原因
连同完整 gates 都在那里。

**测试改动值得记一笔。** 加完这个判据后 `test_evolution_flow.py` 挂了 7
条——原来那套 fixture 没配 `reviewer_factory`，每一轮都停在"no LLM
provider is configured"，也就是说**这批测试一直在通过一条中止路径断言
账本行为**。按新口径它正确地不消费了，测试才暴露出来。给 fixture 补上
`_SilentReviewer` + 一条评测样本 + `min_cases=1, max_cases=1`，让它真的
走完评测，7 条全绿。这是修复在起作用，不是回归。

新增 `UnrelatedAbortTests` 5 条钉住第 16.6 节：safety 拒绝 / 缺 provider /
评测集不足都不消费；**评测后被拒仍然消费**（守反向——放松成"只有激活才
消费"会让循环退回原地打转）；生成器判决不跑评测也消费。

### 19.2 holdout：不是样本太少，是两个问题

样本少只是其中一个。

**问题一：缺陷分母 = 1。** holdout 只有 1 条缺陷样本，`recall` 只有一个
步长。导入 `real-pr-v1` 的 holdout 切片（24 条）+ `mutation-v1`（85 条）
解决。新增 `scripts/import_pr_defect_corpus.py`。

**问题二：`real-pr-v1` 的 holdout 全是 medium**（实测 40 条期望、0 条
high/critical）。所以**再多导它也修不好 `high_severity_recall`**，而那是
参与 decision 的四道受保护指标之一。这才需要第二批语料。

两批必须用不同 `--source` 标签：标签可信度不是一个档次，事后要能分开看、
也要能整批移除。`mutation-v1` 用 `--skip-suspect-labels` 挡掉
`equivalence_status == "no-difference"`（跑过差分执行却没测出行为差异，
假标签集中在这档，85 留 / 15 弃）；`not-attempted` 保留——那只是没探到，
不是证否。

### 19.3 第 17 节的 bug 在严重度维度上复发了

导完 85 条变异样本、表里已有 17 条高危，`high_severity_denominator` 在
`limit=20` 下**仍然是 1**。查库：高危行 id 182–214，缺陷层从 id 26 起，
`positive[:quota]` 按 id 取前 20 条永远够不到它们。**这个 bug 与维度无关
——任何后灌的分层都 id 更大、都取不到。**

这次比上次隐蔽：`clean_accuracy` 分母为 0 时会从报告里消失，而
`high_severity_recall` 分母为 1 时照常打印一个 0.0/1.0 的正常读数。而且它
在 `_protected_metrics` 里是**无条件**受保护的，没有 `clean_accuracy` 那种
`if baseline["clean_cases"]` 把关——分母为 0 时 `_metric_non_regressing`
按"本来没测过，无从回退"放行，它恒通过。**一道分母为 1 的门禁比分母为 0
的更危险。**

修法是 `TaskStore._take_positive`：缺陷层内部再按严重度分一层，每层非空
就至少保 1 条，且高危层不得超过**实际取到的**普通缺陷条数——与
`max_clean_share` 同一条理由（按预算算的上限在对侧存量不足时会失效）。

**顺带修掉一个潜在缺口：** 原来 `if not positive or not clean` 会在干净层
为空时直接退回平铺截断，连严重度那一级也一起跳过。两级管的是两个互相
独立的分母，把内层的生效条件挂在"库里有没有干净样本"上没有道理。现在
拆成两支，并把排序 + 反序列化收进 `_hydrate`（分层拼接天然打乱 id 序，
而指纹按返回顺序算，少排一次就会让同一套样本算出不同指纹）。

### 19.4 结果

`max_cases=20` 下 holdout 构成的完整轨迹：

| 阶段 | 缺陷 | 干净 | 高危 |
|---|---|---|---|
| 第 17 节之后 | 1 | 16 | 1 |
| 导入 real-pr-v1 之后 | 13 | 7 | 1 |
| 导入 mutation-v1 + 修取样之后 | 18 | 2 | 2 |

导入统计（均入 scratch 库，rejected 皆为 0）：`real-pr-v1` inserted=24 /
skipped_other_split=71，严重度全 medium；`mutation-v1` inserted=85 /
skipped_suspect_label=15，medium 69 + high 16。

全量测试 872 passed / 58 subtests（改动前 854）。

### 19.5 诚实的局限

1. **20 条高危样本全部来自 `weakened-guard` 单一变异算子。** 所以
   `high_severity_recall` 现在测的是"对减弱守卫这一类变异的敏感度"，
   **不是泛化的高危召回**。分母从 1 变成 2 是从"没有信息量"变成"信息量
   很粗"，不是变成"够用"。
2. **holdout 干净分母从 16 掉到 2。** 85 条变异缺陷把这个 split 压歪了，
   比例分配随之偏向缺陷层。干净层仍非空（保 1 条的约束在起作用），但
   `clean_accuracy` 在 holdout 上重新变成粗读数。要么限制变异导入量、要么
   补 holdout 干净样本——**未决**。
3. **holdout 指纹必然变了**，第 16.7 节的分数作废，基线要重跑。
4. `real-pr-v1` 自己的 `source.note` 写明"incoming PR"框架是合成的、正例率
   由构造抬高，不可与自然 PR 基准比较。

---

## 20. 回路 A 第一次真实闭合（2026-09-08）

第 19 节的修复只有单元测试在保证，而单元测试用的是 stub 生成器和空评审器
——**它证明不了真实 LLM 生成的候选会不会被拦在评测之前**，而恰恰是那一档
决定反馈该不该被消费。所以真跑了两轮，`scripts/run_loop_a_probe.py`。

库用 `output/feedback-labelling/scratch/defect-import.db` 的副本
（`output/loop-a/round.db`），先清掉第 16.6 节那个缺陷烧掉的 20 条
`evolution_attempts`。主库与 `datasets/` 未触碰。

### 20.1 先撞上一个真实阻塞：候选生成一次都跑不完

第一次跑，round 1 在生成阶段就崩了：

```
RuntimeError: deepseek JSON request failed: model returned empty content
(finish_reason=length, completion_tokens=6000, reasoning_tokens=6000,
max_tokens=6000); raise the token budget for reasoning models
```

`RootCauseEvolutionGenerator` 的 `token_budget` 硬编码 6000，而
`deepseek-v4-flash` 是推理模型，`max_tokens` 同时封顶 reasoning + content
——6000 全被推理吃掉，`content` 是空串。

**第 16.5 节诊断过这个失败，但只修了报错文案，没动预算。** 于是那条精准的
错误消息一直在正确地报告一个从未被修的阻塞，回路 A 至今一次都没真跑起来。
这是"报告不是门禁"的又一次：可诊断性做好了，问题还在。

修法：新增 `evolution_generator_token_budget` 设置
（`EVOAGENT_EVOLUTION_GENERATOR_TOKEN_BUDGET`，默认 **16000**），由
`service.py` 注入 generator，`validate_evolution` 拒绝 < 2000 的配置——
预算不足的运行时表现是"调用成功、content 空串"，那又是一道假装在工作的
环节，必须在启动时就报错。`tests/test_config.py::GeneratorTokenBudgetTests`
4 条钉住，其中一条直接断言默认值必须 > 6000（实测跑不完的那个数）。

### 20.2 两轮的实际结果

| | round 1 | round 2 |
|---|---|---|
| decision | `rejected` | `deferred` |
| reason | 分数提升低于阈值 | 未解决反馈里没有新的可支持信号 |
| `feedback_consumed` | **true** | true |
| `failure_cases_used` | **20** | **0** |
| `already_attempted` | 0 | **20** |
| `evaluation_success` | **true** | null（没进评测） |
| skill_versions | 1 → 2 | 2 |

门禁明细（round 1）：`safety` ✅、`validation_dataset_ready` ✅、
`holdout_dataset_ready` ✅、`validation_non_regression` ✅、
`holdout_non_regression` ✅、**`validation_improvement` ❌**。
`non_regression_unmeasurable` 两侧都是空列表——**受保护指标第一次全部有
分母**，这是第 17 / 19 节两次取样修复的直接结果。

**回路 A 闭合了。** 判据是第二轮的行为必须与第一轮不同：第一轮真进了评测、
消费 20 条；第二轮 `failure_cases_used` 归 0、20 条全部落进
`already_attempted`，生成器**没有被第二次调用**。改动之前这里是重新生成一
次等价候选然后靠字符串比较兜底（第 15 节），或者在无关失败下把反馈一次性
烧光（第 16.6 节）。两种病都不再复现。

### 20.3 候选分数持平，但这轮的信息量在别处

`baseline 0.6375 → candidate 0.6375`，`recall 1.0 / precision 0.6 /
high_severity_recall 1.0` 两侧完全一致，`significant: false`。候选没改善
任何东西，被 `validation_improvement` 正确拒掉。

要注意的是 **validation 侧 `clean_accuracy` = 0.0，而 `clean_cases` = 2**
——分母有了，读数是 0，也就是那 2 条干净样本**全部被误报**。这不是取样
缺陷，是 reviewer 的真实行为：`precision 0.6` 与它一致。第 18.2 节说的
"还没有任何一轮候选是在误报侧有分母的条件下跑出来的"，现在跑出来了，答案
是误报侧确实有问题。

另外 `evolution_runs` 只有 2 行而 `skill_versions` 到了 2：被拒的候选也
存版本（第 19.1 节测试里踩到过——它会被下一轮选作亲本）。

### 20.4 仍然没有闭合的

- **回路 B / C 依旧不存在。** 候选被 `validation_improvement` 拒了，没有
  任何候选通过门禁。这一轮证明的是**门禁在正确工作**，不是候选变好了。
- `max_cases=5`（默认）下 validation 只取 5 条、clean 2 条。第 19.4 节
  测的 20 条是 `max_cases=20` 的形状，两者不能混着读。
- 第 13 节 G 的 Pareto 现在**具备了前置条件**：档案里有两个带分数的版本
  （0.6049 / 0.6375）。但两个版本还不够谈 Pareto 前沿。
- 探针脚本第一版把门禁键名写成 `improved` / `non_regression`（真实键名是
  `validation_improvement` / `validation_non_regression`），取到 None。
  **而 None 在这个项目里恰好是"没跑到"的意思**，于是一个拼写错误被读成
  "这道门禁没执行"。已修，并在 `digest()` 里留了注释。完整 result 逐轮
  落盘，所以不用重跑就能复算。
