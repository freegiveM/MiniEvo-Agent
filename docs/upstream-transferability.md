# 上游同类项目的技术可迁移性评估

写作日期：2026-09-09。

本文档评估三个外部自进化 Agent 项目对本仓库的可借鉴之处，并给出据此的开发
计划。写法沿用 `next-development-plan.md` 的惯例：所有结论给出**双方**的代码
位置，所有"建议这样做"附上"不这样做会怎样"。读者不需要读过之前的对话。

被评估的三个项目 clone 在本仓库之外的一个同级目录（`_reference-repos/`），
**不进版本控制**。本文引用它们时给出各自仓库内的相对路径。

| 项目 | 版本 | 许可 | 语言 |
|---|---|---|---|
| [microsoft/SkillOpt](https://github.com/microsoft/SkillOpt) | main @ 2026-09-09 | MIT | Python |
| [sentient-agi/EvoSkill](https://github.com/sentient-agi/EvoSkill) | main @ 2026-09-09 | Apache-2.0 | Python |
| [alibaba/skill-up](https://github.com/alibaba/skill-up) | main @ 2026-09-09 | Apache-2.0 | Go |

---

## 0. 一句话结论

**可迁移的比预期少，且其中两条我在初读时判断错了，已在第 2 节更正。**

真正值得移植的只有两条半：SkillOpt 的**被拒编辑回流**（本仓库只做了一半）、
SkillOpt 的**编辑预算**（完全没有）、以及 SkillOpt 的**批量规模**（作为
已知问题 P1 的外部佐证，不是新设计）。

三个项目在**门禁**这一维度上**全部弱于本仓库**，不应参考。这一点很重要，
因为它决定了本仓库当前那个未决缺陷（第 4 节）只能自己定方案，抄不到。

---

## 1. 三个项目各自在做什么

三者共同的形态是**冻结模型权重，把自然语言技能文档当作可训练参数**。这与
本仓库的 `skill_versions.prompt` 是同一个思路，所以对比才有意义。

- **SkillOpt**：把提示词优化写成一个神经网络训练循环——epoch、minibatch、
  learning rate、scheduler、validation gate 一应俱全。`learning_rate` 被
  重新定义为"每步最多改几处"。
- **EvoSkill**：从**失败轨迹**里合成可复用的 skill 文件夹，用 git 分支存放每
  个 agent program，用 git tag 标记"frontier"。
- **skill-up**：不做进化，只做**评测**——声明式 YAML 用例、多引擎（Claude
  Code / Codex / Qoder）、`rule_based` / `script` / `agent_judge` 三种判分，
  面向 CI 回归。进化能力由一个叫 `skill-upper` 的 skill 驱动。

---

## 2. 两处必须更正的初读判断

初读这三个仓库时我给出过两条判断，查证本仓库代码后**都是错的**。先更正，
因为整份可迁移性评估的基线依赖它们。

### 2.1 更正一：本仓库的 Pareto 不是"未做"，而是强于 EvoSkill

我此前说"P3 Pareto 尚未实现，可参考 EvoSkill"。**两半都不对。**

本仓库 `evoagent/archive.py:139` 的 `pareto_frontier` 是**逐样本前沿**：

```
对每一个 case，找出在它上面取得最高分的版本；
所有"在至少一个 case 上是最优"的版本构成前沿。
```

配套的 `frontier_weights`（`archive.py:169`）按"在多少条 case 上领先"给权
重，`select_parent`（`archive.py:192`）据此做确定性加权采样。这是 GEPA
（arXiv:2507.19457）的原始定义。

而 EvoSkill 的 `update_frontier`
（`_reference-repos/EvoSkill/src/registry/manager.py:378`）实际是这样：

```python
if len(scored) < max_size:
    self.mark_frontier(name); return True
worst_name, worst_score = scored[-1]
if score > worst_score:
    self.unmark_frontier(worst_name); self.mark_frontier(name); return True
```

**按单个标量分数取 top-K**（默认 K=3），没有任何支配关系判定，没有多目标。
它叫 frontier，但它是一个排行榜。一个总分略低、却在三条别人全错的 case 上
唯一正确的版本，在 EvoSkill 里会被淘汰，在本仓库里会进前沿——`archive.py:145`
的注释正是在说这件事。

**结论：这个方向不存在可迁移物，方向是反的。** 本仓库真正缺的不是算法，是
档案里只有两个版本（0.6049 和 0.6375），两个点构不成前沿。这是数据量问题，
不是实现问题，归入第 5 节 P1。

### 2.2 更正二：被拒判决已经回流，缺的是"改了什么"和"掉了多少"

我此前说"候选被拒后那次尝试就蒸发了，下一轮可能提出同一个改法"。**前半错，
后半对。**

本仓库 `evoagent/evolution.py:1064` 的 `_prior_attempts` 已经在做回流：

```python
prior.append({
    "root_cause_fingerprint": row.get("fingerprint"),
    "decision": row.get("decision"),
    "reason": row.get("reason"),
    "candidate_version": row.get("candidate_version"),
})
```

而且只回传**与本轮根因相关**的尝试（`evolution.py:1075` 按 fingerprint 过
滤），理由写在 docstring 里：无关根因的记录挤占 token 预算，且容易被模型误读
成"这个方向也别碰"。这比 SkillOpt 的 step buffer 更克制——后者把整个 epoch
内的所有 step 不加过滤地拼进去（`_format_step_buffer`，
`_reference-repos/SkillOpt/skillopt/engine/trainer.py:619`）。

**真正缺的是两个字段。** 生成器现在拿到的是"版本 3 被拒了，因为
severity_accuracy 回退"，拿不到"版本 3 具体动了哪几处"和"分数从 0.62 掉到
0.55"。`evolution_attempts` 表（`store.py:159`）里没有这两列。

对比 SkillOpt 喂给 optimizer 的形态：

```
### Step 12 — REJECT (7/40 failed)
  - "unit mismatch: ..." (×3, tasks: 41, 88, 90)
  Rejected edits (score 0.62 → 0.55):
    1. [insert] target="## Verify" → "ALWAYS restate units"
```

差别在于：只给"被拒 + 理由"，模型知道方向错了但不知道**哪一处**错了，于是
下一轮很可能换个措辞重提同一处修改；给出具体编辑，模型才能定位。

**这条可迁移，且成本比我初判的低**——见第 3.1 节。

---

## 3. 可迁移项

### 3.1 被拒编辑的内容与分数落差（P0）

**上游位置**：`_reference-repos/SkillOpt/skillopt/engine/trainer.py:619`
（`_format_step_buffer`）与 `trainer.py:1645`（buffer 装配）。

**本仓库位置**：`evoagent/evolution.py:1064`（`_prior_attempts`）、
`evoagent/store.py:159`（`evolution_attempts` 表）。

**为什么成本低**：候选提示词的全文**已经存在** `skill_versions.prompt` 里，
而 `evolution_attempts.candidate_version` 已经记了版本号。也就是说
"改了什么"是可以从现有两张表 join 出来的，不需要新增存储，只需要在
`_prior_attempts` 里按 `candidate_version` 取回候选提示词，与亲本做 diff。

真正需要新增的只有分数落差。两个选择：

- **（a）新增两列** `score_before` / `score_after` 到 `evolution_attempts`。
- **（b）不新增**，从 `evolution_runs` 按 `run_id` 取回完整 metrics。

倾向 **(b)**：`evolution_attempts.run_id` 已是外键式的关联，metrics 全文在
`evolution_runs` 里，新增列会让同一个数字有两个存放处，两处不一致时无法判断
谁对。仅当 join 的成本被证明不可接受时才退到 (a)。

**不这样做会怎样**：生成器在同一个根因上反复提出措辞不同、实质等价的修改。
这正是 `next-development-plan.md` 第 1 节第 3 项当初要修的问题——那次只修到
"知道被拒了"，没修到"知道哪处被拒了"，属于同一个缺陷的后半段。

**风险**：diff 会显著撑大生成器的输入。必须设上限并在超限时截断（截断这件事
本身要写进传给模型的文本，否则模型会把"没提到的编辑"读成"没做过的编辑"）。

### 3.2 编辑预算（P1）

**上游位置**：`_reference-repos/SkillOpt/configs/_base_/default.yaml`

```yaml
optimizer:
  learning_rate: 4          # max edits per step (edit_budget)
  min_learning_rate: 2      # min edits for decay schedulers
  lr_scheduler: cosine      # constant / linear / cosine / autonomous
```

配置键映射见 `_reference-repos/SkillOpt/skillopt/config.py:136`
（`"optimizer.learning_rate": "edit_budget"`）。

**本仓库现状**：候选生成是不设上限的自由重写，`_generate_candidate`
（`evolution.py:1088`）对生成器返回的提示词长度和改动量都不做约束。

**为什么值得**：改动量有界之后，第 3.1 节的被拒编辑列表才能逐条列出来——
一次改了 30 处的候选，即使记下了 diff，模型也无法归因到具体某一处。**这两项
有依赖关系，3.2 是 3.1 的前置放大器**，但 3.1 可以先独立落地。

**不这样做会怎样**：提示词漂移。每轮自由重写会让提示词逐渐膨胀、互相矛盾，
而门禁只看指标，不看提示词本身是否还自洽。

**注意**：scheduler（cosine 衰减）**先不抄**。本仓库的轮次数是个位数，衰减
曲线在 3 轮里退化成噪声；先做固定预算（`constant`），等轮次上到两位数再谈。

### 3.3 批量规模：P1 的外部佐证（非新设计）

SkillOpt 的默认配置：`train.batch_size: 40`、`gradient.minibatch_size: 8`，
且**选择集单独配置**（`evaluation.sel_env_num`）。

本仓库 `eval_max_cases` 原默认 5（环境变量 `EVOAGENT_EVAL_MAX_CASES`），实测
validation 里只有 3 条 positive + 2 条 clean。

这不是一个新发现——本仓库已经实测出后果（`severity_accuracy` 的分母是 2 或
3，一条样本移动 33 个百分点）。SkillOpt 的 40 / 8 与 5 差了近一个数量级，
给"默认值该往哪个量级调"提供了一个外部参照点。

**已调整**（`config.py` / `evolution.py` 构造函数默认值，两处同步）：默认值
抬到 **20**，validation 取 10 缺陷 + 10 干净，holdout 取 18 + 2，两个方向的
分母都进入两位数。没有直接跟到 40：单轮回放次数是 `4 × max_cases`（两个切分
× baseline/candidate），20 已经是每轮 80 次 LLM 调用，再往上收益递减而成本
线性涨。库存不是瓶颈（validation 23 缺陷 + 65 干净），这纯粹是预算取舍。

### 3.4 声明式评测用例（P3，选做）

**上游位置**：`_reference-repos/skill-up/examples/code-stats/evals/`。

skill-up 的 case 是 YAML：

```yaml
expect:
  must_contain: ["Files by Extension", "Total Lines"]
  must_not_contain: ["error"]
judge:
  type: script
  script_path: evals/fixtures/scripts/check-stats.sh
```

**与本仓库的关系**：本仓库的评测集是 `datasets/real-pr-v1.jsonl`，每条带
`expected_findings`，判分逻辑写死在 `evaluation_harness` 里。这是**为代码
审查这一个任务定制的**，比 skill-up 的通用 `must_contain` 精确得多——
`must_contain` 无法表达"在 `foo.py:42` 报出 CWE-89"。

**因此不建议替换判分逻辑。** 唯一值得考虑的是它的**多引擎抽象**（同一份
用例跑 Claude Code / Codex / Qoder），如果将来要证明"进化出的提示词可以跨
模型迁移"，这个形状可以参考。当前没有这个需求，列为 P3 选做。

---

## 4. 不可迁移项，以及一个只能自己解决的缺陷

### 4.1 门禁：三个项目全部弱于本仓库

SkillOpt 的门禁（`_reference-repos/SkillOpt/skillopt/evaluation/gate.py`，
全文 225 行）核心是一行：

```python
if cand_score > current_score:
```

单标量比较，`hard` / `soft` / `mixed` 三选一。**没有**逐指标非回归检查、
**没有**置信区间、**没有**"未测量"与"测得为零"的区分。

EvoSkill 同样是单标量（见 2.1）。skill-up 是 CI 式的 pass/fail 退出码。

本仓库的 `_protected_metrics`（`evolution.py:1174`）对
`score` / `precision` / `recall` / `high_severity_recall` 逐个做非回归检查，
带 Wilson 置信区间（`evolution.py:354`），且严格区分 `None`（没测）与 `0.0`
（测了没中）——`_empty_metrics`（`evolution.py:1163`）的注释专门说明了为什么
区间是 `None` 而不是 `[0,0]`。

**结论：这个方向没有可迁移物。** 记录在此是为了防止后续有人"参考上游"把
门禁改简单——那会是一次实质性的能力倒退。

### 4.2 `severity_accuracy` 门禁惩罚召回提升（未决，抄不到方案）

**现象**：Loop B 第一轮候选 v3 被拒，理由 `a protected validation metric
regressed (severity_accuracy)`，1.0 → 0.6667。

**但候选没有把任何一条原本判对的判错。** 逐样本核对：基线漏掉的那条
missed_issue，候选抓到了（`tp=1 fn=0 sev_hits=0`）。

根因在 `evolution.py:311`：

```
severity_accuracy = severity_hits / matched
```

分母是**匹配数**。多抓到一条缺陷，分母就被自己撑大：基线 2/2 = 1.0，候选
2/3 = 0.667。其余指标全线上升（precision 0.5→1.0，recall 0.6667→1.0，
clean_accuracy 0.5→1.0，holdout 0.3639→0.49），置信区间几乎完全重叠
（[0.342,1.0] vs [0.208,0.939]），`significant: false`。

**门禁惩罚的是召回率提升。**

**为什么抄不到方案**：这三个项目都不会遇到这个问题，因为它们的门禁只看一个
标量（4.1）。本仓库遇到它，恰恰是因为做了多指标非回归检查——这是更难但更对
的方向。方案只能自己定。

两个候选修法：

- **（a）** 候选 `matched` 大于基线时，改比**绝对** `severity_hits`。
- **（b）** 分母不同时把该指标列为 `unmeasurable`——`evolution.py:1210` 已有
  这个机制，不需要新造概念。

倾向 **(b)**：不引入新语义，且与 `_empty_metrics` 那套"没测就说没测"的既有
口径一致。(a) 的问题是"绝对命中数不回退"在样本增加时同样会误判。

**在得到确认前不动这段代码**——它是全系统唯一的抗过拟合检查，改错的代价
高于它现在误拒一个候选的代价。

---

## 5. 开发计划

排序原则：**先修正在产生错误判决的，再补信息缺失的，最后做放大器。**

| # | 事项 | 优先级 | 依赖 | 预计改动面 |
|---|---|---|---|---|
| 1 | `severity_accuracy` 门禁修正（4.2，方案 b） | P0 | 需用户确认方案 | `evolution.py` 单文件 + 单测 |
| 2 | 被拒编辑内容回流（3.1，方案 b） | P0 | 无 | `evolution.py` + 单测 |
| 3 | `eval_max_cases` 默认值上调（3.3） | P1 | 事项 1（否则分母问题掩盖效果） | `config.py` 两处 |
| 4 | 编辑预算（3.2，固定预算，不做 scheduler） | P1 | 事项 2（否则 diff 无法归因） | 生成器接口 + `config.py` |
| 5 | 档案版本数增长以支撑 Pareto（2.1） | P2 | 事项 1、3 | 无代码改动，需跑轮次 |
| 6 | 多引擎评测抽象（3.4） | P3 | 无 | 大，且当前无需求 |

### 事项 1：`severity_accuracy` 门禁修正

在 `_protected_metrics` / 非回归报告中，当候选与基线的 `matched` 不同时，将
`severity_accuracy` 标为 `unmeasurable`，复用 `evolution.py:1210` 的既有机制。

**验收**：Loop B 第一轮的那个候选 v3 重跑后不再因该指标被拒；新增单测覆盖
"分母不同 → unmeasurable"与"分母相同且真实回退 → 仍然拒绝"两条路径。第二条
必须有，否则这次修改会把门禁改成永远不检查这个指标。

**阻塞**：等用户在方案 (a) / (b) 之间确认。

### 事项 2：被拒编辑内容回流

在 `_prior_attempts`（`evolution.py:1064`）返回的每条记录上补两个字段：

- `edits`：由 `candidate_version` 从 `skill_versions.prompt` 取回候选提示词，
  与亲本做 diff，截断到上限；截断事实本身写进文本。
- `score_delta`：由 `run_id` 从 `evolution_runs` 取回 metrics（方案 b，不新增
  列）。

`decision == "rejected"` 时才附这两个字段——被激活的候选不需要"别再这么改"
的信号。

**验收**：单测断言被拒轮次的 `prior_attempts` 含具体 diff 与分数落差；断言
截断发生时文本里有显式说明；断言激活轮次不含这两个字段。

**风险**：token 预算。上限值需实测后定，不要凭感觉写死。

### 事项 3：`eval_max_cases` 默认值

上调 `config.py:142` / `config.py:351` 的默认值。**具体数值待定**——需要先
统计 `datasets/real-pr-v1.jsonl` 里 validation 分片的实际容量，取"不超过可用
量"与"分母足够稳"的交集。SkillOpt 的 40 是参照，不是目标。

**必须排在事项 1 之后**：现在分母问题还在，调大样本量会让"指标变化"混合了
两个原因，无法归因。

### 事项 4：编辑预算

给候选生成器加一个"本轮最多改 N 处"的约束，`constant` 策略，不做 scheduler
（3.2 已说明理由）。

**必须排在事项 2 之后**：预算的价值在于让 diff 可归因；没有 diff 回流时，
限制改动量只是单纯的能力削减。

### 事项 5：档案版本数

无代码改动。事项 1、3 完成后跑若干轮，让 `skill_versions` 里的版本数从 2 增
长到足以构成前沿。`archive.py:149` 已经处理了"没有逐样本数据时返回空列表"，
不会因为版本少而误判。

---

## 6. 本次评估没有改动任何代码

三个上游仓库 clone 在 `_reference-repos/`，**在本仓库之外**，不会被提交。
本文档是唯一产物。第 5 节的事项 1 需要用户在两个方案间确认后才开始。