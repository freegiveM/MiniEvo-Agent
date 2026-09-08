# 真实 PR 评测数据集（reverted-fix 构造）

本目录是评测链路的地基。数据集不入库（体积 + 可复现），由采集器按
`repos.yaml` 重新生成。

## 一、构造方法：反转已合并的 bugfix PR

```
真实 fix PR:  digest = hashlib.md5(x)    →    digest = hashlib.sha256(x)
                    （删除行）                    （新增行）
       ↓ 反转 diff
待审 PR:      digest = hashlib.sha256(x)  →   digest = hashlib.md5(x)
                                                （新增行 = 种子缺陷）
标注: 该新增行 = 一个种子缺陷, CWE 取自修复类别
```

### 为什么反转 diff，而不是"取父提交快照"

两个硬理由，不是风格选择：

1. **Agent 审的是变更，不是状态。** "取父提交作为待审输入"在口径上是含糊的
   ——父提交是一个仓库状态，不是一次变更。反转 diff 给出的是一个语义明确的
   待审变更，和生产路径（审 PR diff）完全同构。

2. **现有校验器强制要求标注落在新增行上。** `evaluation_harness.validate_case`
   有这一条硬约束：
   ```python
   raise ValueError("%s finding does not cover an added line" % prefix)
   ```
   反转构造天然满足，父提交快照不满足。这不是巧合——它反映了"只审新增行"
   这个贯穿全项目的原则。

### 诚实标注

`source.kind = "real-pr-reverted-fix"`，**不是** `public-github-pr`。

代码内容是真实的（那段有缺陷的代码确实在仓库历史里存在过），但"这是一个
待审 PR"这个框架是构造的。真实 PR 的分布里有大量无风险变更，本数据集按
缺陷筛出，**正样本比例被人为拉高**，因此不能与 SWR-Bench 之类横向比较。

## 二、数据污染防护（pre/post-cutoff 切分）

反转公开 fix PR 有一个绕不开的问题：**这些 PR 在模型预训练数据里**。

- 《The SWE-Bench Illusion》(arXiv:2506.12286) 证明模型**不看仓库、仅凭
  problem statement** 就能复现有缺陷的文件路径——它在回忆，不在推理。
- OpenAI 已停用 SWE-bench Verified 作为前沿能力指标。
- SWE-bench Verified 那 93 名开发者的人工筛查针对**任务质量**，
  从未过滤训练数据污染；500 个实例全部来自 2023 年前的公开 PR。

因此每条记录带 `merged_at`，并按模型知识截止切两个子集，**分别报数**：

| 子集 | 定义 | 用途 |
|---|---|---|
| `pre-cutoff` | 合并于模型知识截止之前 | 可能被记忆 |
| `post-cutoff` | 合并于知识截止之后 | 干净 |

两子集种子召回接近 → 有力证据说明测的是能力而非记忆。
post 明显更低 → 自己发现了污染，主动报告。

方法来源：微软 **SWE-bench-Live** 的立项前提正是"持续从近期 PR 重新采集
以规避污染"。

## 三、难度分级与缺陷分类

### 3.1 难度四级（覆盖梯度，不是只挑好做的）

难度定义为**定位与归因所需的上下文范围**，这是可客观判定的，不靠主观感觉：

| 级别 | 定义 | 判定规则 | 目标占比 |
|---|---|---|---|
| **L1 单行字面** | 缺陷在单行内且有字面特征 | 1 行改动，规则可正则命中 | ~25% |
| **L2 单函数** | 需读完整个函数才能判定 | 改动集中在 1 个函数体内 | ~35% |
| **L3 跨函数/跨文件** | 需追调用链或跨文件对照 | 改动跨 ≥2 函数或 ≥2 文件 | ~25% |
| **L4 语义/并发/状态** | 需理解运行时语义 | 涉及并发、资源生命周期、状态机 | ~15% |

L1 是下界校准（连 L1 都漏说明规则集有问题），L4 是上界探测
（**预期大量失败，这是信息不是失败**）。

> 为什么必须覆盖 L3/L4：只报 L1/L2 的数字会虚高，且无法回答
> "你的系统边界在哪"。分级报告能直接给出能力曲线，而不是一个平均数。

### 3.2 缺陷分类（八类，映射到 CWE）

| 类别 | 典型 CWE | 典型形态 | 难度倾向 |
|---|---|---|---|
| `crypto-weak` | CWE-327/328 | md5/sha1 用于安全场景、弱随机 | L1 |
| `injection` | CWE-78/89/94 | shell=True、字符串拼 SQL、eval | L1–L2 |
| `secret-exposure` | CWE-798/532 | 硬编码凭据、日志打印敏感信息 | L1–L2 |
| `path-traversal` | CWE-22 | 未校验的路径拼接、zip 解压 | L2 |
| `auth-bypass` | CWE-285/862 | 权限检查缺失或顺序错误 | L2–L3 |
| `resource-leak` | CWE-772/400 | 文件/连接未关闭、无超时 | L2–L3 |
| `logic-boundary` | CWE-193/125 | off-by-one、边界判断错误 | L2–L3 |
| `concurrency` | CWE-362/367 | 竞态、TOCTOU、共享状态 | L4 |

**每类至少 6 例**，避免单类主导指标。

### 3.3 规模

**设计目标**：80–100 个 PR，14–18 个仓库，仓库不相交切分
Validation / Holdout（约 11 : 5 仓库，约 70% : 30%）。

**`real-pr-v1.jsonl` 实际落地**（2026-09-07 从数据集实测，不是从设计目标抄的）：

| 项 | 设计目标 | 实际 |
|---|---|---|
| 用例数 | 80–100 | **95** |
| 仓库数 | 14–18 | **15** |
| 仓库切分 | 约 11 : 5 | **11 : 4** |
| 用例切分 | 约 70% : 30% | **71 : 24（74.7% : 25.3%）** |

仓库不相交已实测校验：两侧仓库集合交集为空。

**仓库不相交是硬约束**：同仓库的 PR 共享代码风格、目录结构和惯用法，
切在 PR 级别会让 holdout 泄漏。

### 3.4 已知局限（实测，非设计）

这三条都是从 `real-pr-v1.jsonl` 直接统计出来的，写在这里是因为它们会
影响任何基于这份数据的结论怎么解读。

**1. 没有 L1 档样本。** 难度分布是 `L2: 60 / L3: 30 / L4: 5`，L1 为 **0**。
§3.2 的缺陷类表格里 `injection`、`secret-exposure` 都标着 L1–L2，但筛选
规则（§5：修复改动 ≤ 20 行、排除重构与格式化）加上"来自真实已合并 fix
PR"这个前提，天然筛掉了 L1——最直白的注入和硬编码凭据很少能活到进入
主干再被单独修一次。后果：**这份数据不能用来声称"能检出简单缺陷"**，
它只证明了 L2–L4 上的表现。要覆盖 L1 得另造合成样本，那属于另一份数据集。

**2. `rule_covered` 只有 3/95。** 即 95 条里只有 3 条被现有确定性规则集
覆盖。所以规则命中率这个指标在这份数据上**没有分母可言**，任何"规则集
覆盖了多少缺陷"的结论都不能从这里得出。反过来说，这 95 条基本都在考
LLM reviewer 的语义判断，而不是规则匹配。

**3. `expected_findings` 是按变更 hunk 行自动派生的，不是逐条人工标注的。**
后果是纯字符串、注释、import、覆盖率标记这类行也会成为"expected"。
实例：`encode__httpx-pr-3042` 的**唯一** expected finding 是一行新增的
`# pragma: no cover`，而同一个 PR 里删掉 cookies 弃用告警、删文档段这些
实质改动**没有**被标进去。所以 `unmatched_expected` **不等于**"reviewer
本该报却漏了"，用它算召回会低估。详见 `docs/next-development-plan.md`
第 16 节。

**4. `diff` 字段是反转后的方向。** `diff` 的 `+` 侧携带种子缺陷，
`human_patch` 是把它反过来的真实修复。这一条已在 `aio-libs__aiohttp-pr-12796`
上逐字段对比核实过。读这份数据的任何脚本都得按这个方向理解，反了会把
缺陷侧当成修复侧。

## 四、候选仓库清单

选择标准（每条都有理由）：

| 标准 | 理由 |
|---|---|
| 纯 Python 或 Python 为主 | 规则集只覆盖 Python，语言范围必须收敛 |
| 有活跃的 bugfix / security 记录 | 保证能筛出足够样本 |
| 有可运行的测试套件 | 修复环节的 before/after 对照需要它 |
| 领域分散 | 避免全部是 web 框架，否则缺陷类型单一 |
| 包含近期 PR（post-cutoff） | 污染对照的必要条件 |

见 `repos.yaml`。清单按领域分组，覆盖 web / 数据 / 基础库 / 运维工具 /
安全工具五类，避免领域单一导致缺陷类型偏斜。

## 五、筛选规则（降标注噪声）

| 规则 | 理由 |
|---|---|
| PR 标题或关联 issue 命中 fix/bug/security/CVE 关键词 | 排除 feature PR |
| 修复改动 ≤ 20 行、≤ 3 文件 | 集中修复才能定位"缺陷就在这几行" |
| 排除 revert / 重构 / 格式化 / 依赖升级 / 纯测试改动 | 这些的"删除行"不是缺陷 |
| 必须触碰非测试的 `.py` 文件 | 语言范围收敛 |
| 反转后新增行必须非空且非纯注释 | 防止空标注 |
| 必须能通过 `validate_case` | 与既有校验器一致 |

## 六、字段说明

除 `validate_case` 要求的字段外，额外记录：

| 字段 | 用途 |
|---|---|
| `merged_at` | pre/post-cutoff 切分 |
| `contamination_split` | `pre-cutoff` / `post-cutoff` |
| `difficulty` | `L1`–`L4` |
| `defect_class` | 八类之一 |
| `human_patch` | **人类原始修复补丁**——修复环节评测的真值（免费红利） |
| `fix_pr_url` | 可追溯，第三方能复核标注 |
| `label_provenance` | 标注来源：`title-keyword` / `linked-issue` / `cve` |

`human_patch` 是反转构造的意外收益：每条数据自带人类的真实修复，
使修复环节可以免费获得真值，无需额外标注。

## 七、复现

```bash
export GITHUB_TOKEN=...   # 需要 token：未认证限额 60 次/小时，不够用
python scripts/collect_reverted_fix_dataset.py \
    --repos datasets/repos.yaml \
    --output datasets/real-pr-v1.jsonl \
    --target 100
```

采集器是幂等的：`--resume` 会跳过已采集的 PR，便于 rate limit 下分批跑。

## 八、Clean split（负样本）

### 为什么需要它

一到七节描述的正样本集，每条 case 都由 `dataset_builder.build_case`
反转一个**已验证的真实 bugfix PR** 构造而来——也就是说每条待审 diff
附近**保证**存在一个已知缺陷。reviewer 面对的因此不是"这段代码有没有
问题"的开放判断，而是"在已知有针的干草堆里找针"。在这批数据上跑出
接近 100% 的命中率，测的是"在已知缺陷位置上会不会漏报"（recall-like），
**测不出假阳性率**：一个逢可疑写法就报的 reviewer，同样能在这种构造下
跑出很高的分数。

`evolution.py` 的打分公式里权重 0.20 的 `clean_accuracy`（≈ 1 − FPR）
分量因此在真实数据评测里从未真正参与过打分——`clean_total` 恒为 0，
只在少数手写玩具用例里跑过。Clean split 就是为了填上这个从未被测过的
维度。

### 构造方法

从**已经产出正样本的同一批仓库**里，再采一批"看起来不像 bugfix 的
普通已合并 PR"，`expected_findings = []`。不引入新仓库，控制代码风格 /
领域这个协变量；复用现有 PR 抓取与解析逻辑，只是筛选方向相反：

| 规则 | 理由 |
|---|---|
| 标题+正文**不**命中 `FIX_KEYWORDS`（`screen_title_for_clean`，对 `screen_title` 取反） | 排除自称是 bugfix 的 PR |
| 仍然过滤 revert / backport / 发版 / 依赖升级等（与正样本共用同一批排除规则） | 这些不是 organic 的普通改动，纳入会引入另一种偏置 |
| `merged_at` 距采集时刻（`as_of`）≥ `CLEAN_COOLDOWN_DAYS`（默认 180 天） | 给"后续没被回滚/重新修复"留出观察窗口 |
| 复用正样本同一套规模 / 语言约束：≤`MAX_FIX_FILES` 文件、≤`MAX_FIX_LINES` 行、必须触碰非测试 `.py`、通过 `validate_case` | 与正样本同一构造粒度，可比 |

### 冷却期是代理信号，不是证明

`CLEAN_COOLDOWN_DAYS` 冷却期检查回答的问题是"这段代码合并后，在
观察窗口内**有没有**被人发现的缺陷修复覆盖过"，**不是**"这段代码
已被验证没有缺陷"。本项目**没有**做"核查该文件后续提交历史，确认
未被任何 bugfix PR 覆盖"这一步 API 级验证——需要额外抓取每个候选
文件的完整后续提交历史，成本远超本项目其余采集调用总量。冷却期只是
一个更便宜的代理：未被发现 ≠ 已验证无缺陷。这个局限如实记在每条
clean case 的 `source.note` 字段里，不是事后才发现的缺口。

### 诚实标注

`source.kind = "real-pr-clean"`，与正样本的 `real-pr-reverted-fix`
对称、同样明确区分于 `public-github-pr`。`human_patch` 置空（没有
修复可言），`difficulty` / `defect_class` 均为 `None`（对空标注跑
难度分级 / 缺陷分类没有意义）。

### 为什么单独出一个文件，不并进 `real-pr-v1.jsonl`

`evolution.py` 的 D6 replay 是按整份数据集跑的，"重放 real-pr-v1.jsonl"
这句话现在的含义是"重放正样本集"。把负样本混进同一个文件会让这句话
的含义悄悄变化，且调用方无法再选择"只跑正样本"。分文件
（`datasets/real-pr-clean-v1.jsonl`）后，两种跑法都可以显式声明，
互不干扰。

### 复现

负样本采集默认关闭——不传 `--clean-target` 就不采，即使
`repos.yaml` 里配了 `clean_target_prs` / `clean_target_total` 也一样，
这两个字段只是信息性的参考配额，不是自动开关：

```bash
export GITHUB_TOKEN=...
python scripts/collect_reverted_fix_dataset.py \
    --repos datasets/repos.yaml \
    --output datasets/real-pr-v1.jsonl \
    --clean-output datasets/real-pr-clean-v1.jsonl \
    --target 100 \
    --clean-target 100
```

正负两路复用同一次分页与 diff 抓取（不产生额外 API 请求），按各自
配额分别计数、分别去重，且互斥：同一个 PR 不会同时出现在两个输出里，
一个看起来像 bugfix 的标题也不会因为"正样本配额已满、负样本配额还有
空位"就被当成负样本收进去。

## 九、评测口径：行容差与置信区间

这一节记录两处**尺子本身**的修正。它们不改 reviewer，只改"怎么算命中"和
"这个数字有多可信"，但对报出来的指标影响比多数模型改动都大——D6 全量
replay 的 `high_severity_recall` 从 0.11 变成 0.28，**没有重跑任何一次
API 调用**，差的全是尺子。

### 9.1 行容差对齐到 ±2

`RegressionEvaluator` 原来是精确行匹配（容差 0），而同一个项目里
`evaluation_harness.one_to_one_match` 默认 `line_tolerance=2`，
`docs/alert-rubric.md` 也明写标注的 ±2 必须与评测的 `line_tolerance`
一致。两把尺子刻度不同，两边的数字就不能相互解释。现已统一到 2。

这不是放宽标准。D6 实测里，18 条 high/critical 期望有 4 条 reviewer 明明
定位到了同一处缺陷，只因行号差 1-7 行被判成漏报（`paramiko-pr-1065` 报
214 行、期望 213；`mitmproxy-pr-8326` 报 54、期望 53）。diff 里相邻几行
属于同一个语句是常态，要求行号精确相等测的是"reviewer 报的是缺陷的第几
行"，不是"有没有发现这个缺陷"。容差仍然有限：报到十几行开外照样算漏，
且窗口外的多余 finding 仍然计假阳性，precision 不会被免费抬高。

同时 `expected_finding` 的 `end_line` 现在会一并传入——它本来就是行区间，
只比 `start_line` 会把"报在缺陷区间中段"误判成漏报。

配对顺序也改了：先按距离近、再按严重度高。原来先按严重度挑，会让一条
报在容差边缘的 critical 抢走本该属于近处期望的配对。

改动前后（同一份 checkpoint，零 API 调用）：

| 指标 | 容差 0 | 容差 2 |
|---|---|---|
| precision | 0.7265 | 0.7692 |
| recall | 0.5152 | 0.5455 |
| f1 | 0.6028 | 0.6383 |
| high_severity_recall | 0.1111 | 0.2778 |
| severity_accuracy | 0.8824 | 0.8778 |
| clean_accuracy | 0.7308 | 0.7308 |

`clean_accuracy` 纹丝不动是对的：负样本没有 expected，行容差碰不到它。
`severity_accuracy` 微降也是对的：容差放开后多配上的条目里有严重度没达标
的，分母涨了分子没同比涨。这两条是自洽性检查，不是噪声。

### 9.2 Wilson 置信区间（报告项，不接门禁）

`RegressionEvaluator.run` 现在给每个比例型指标额外输出 95% Wilson score
区间：`precision_ci` / `recall_ci` / `severity_accuracy_ci` /
`high_severity_recall_ci` / `clean_accuracy_ci`。纯新增，原有点估计字段的
语义和取值一个都没变。

用 Wilson 而不是正态近似：后者在小样本或 p 贴近 0/1 时给出退化或越界的
区间（18/18 会算出 `[1.0, 1.0]`，宣称"确定无疑"），Wilson 在两端自动收缩
且永远落在 [0,1] 内。分母为 0 时是 `None`，与点估计的空分母口径一致。

`f1` 不给区间：它不是简单比例（分母 `2tp+fp+fn` 里的样本不独立），套
Wilson 会得到一个看着像置信区间、实际没有对应统计含义的数。

**当前数据规模下区间很宽，这是如实反映局限，不是要调窄的瑕疵。** D6 实测：

| 指标 | 点估计 | 95% 区间 | 宽度 |
|---|---|---|---|
| precision | 0.7692 | [0.6851, 0.8363] | 0.15 |
| recall | 0.5455 | [0.4693, 0.6195] | 0.15 |
| severity_accuracy | 0.8778 | [0.7943, 0.9304] | 0.14 |
| clean_accuracy | 0.7308 | [0.6232, 0.8166] | 0.19 |
| high_severity_recall | 0.2778 | [0.1250, 0.5087] | **0.38** |

最后一行是重点：分母只有 18，区间宽度 0.38。**在这个规模下，
`high_severity_recall` 的任何"提升了多少"都说不出口**——这也是为什么
`docs/severity-rubric.md` 那轮重标要先修分母。前四项分母在 78-117 之间，
区间收到 0.15 左右，可以用来做粗粒度比较。

门禁里新增 `gates["significant"]` / `gates["holdout_significant"]`，判据是
候选与 baseline 的区间是否不重叠。**只展示，不参与 `decision` 的
rejected/activated 判断。** 原因：现有阈值判断已经跑过一段时间、行为可
预期，直接改成显著性判断会让大量原本能通过的候选突然被拦，这个变化要先
观察一段时间报告数据再决定要不要真接入。三态：True / False / None，
None = 一个区间都算不出来，此时"显著与否"无从判断，不能塌成 False。

区间不重叠是"差异显著"的保守充分条件而非充要条件（两个 95% 区间轻微重叠时
差异仍可能显著，严格做法是对差值本身做检验）。这里刻意取保守那一侧：这个
字段只用于报告"我们有多确信"，宁可少报显著也不要多报。

## 十、分档报数：污染、切分、正负样本

`python scripts/report_replay_strata.py`（**零 API 调用**，从
`d6-replay.checkpoint.jsonl` 重放，结果写 `output/real-pr-regression/d6-strata.json`）

### 10.0 为什么补这一节

第二节承诺"按模型知识截止切两个子集，**分别报数**"，但
`contamination_split` 此前只在构造侧（`dataset_builder.py`）出现，
**评测侧一次都没用过**——D6 报出的每个数都是 pre+post 混算的。这是本仓库
最大的一处"说了没做"。

脚本复用 `RegressionEvaluator` 本身而不是自己重算混淆矩阵，否则会出现
第二把尺子（同 9.1 的教训）。不分档重跑一次的结果必须与 `d6-replay.json`
逐字段相等，脚本自带这个断言，不通过直接退出。

### 10.1 污染分档（本节的主要结论）

| 档 | cases | precision | recall |
|---|---|---|---|
| post-cutoff（干净） | 139 | 0.7921 [0.703, 0.860] | 0.5634 [0.481, 0.642] |
| pre-cutoff（可能被记忆） | 34 | 0.6250 [0.386, 0.815] | 0.4348 [0.256, 0.632] |

**post-cutoff 不低于 pre-cutoff，两档区间大幅重叠。**

按第二节的判据："两子集种子召回接近 → 有力证据说明测的是能力而非记忆"。
这里 post 甚至略高，方向与"靠记忆刷分"相反——若模型在背答案，它应当在
训练数据里见过的 pre-cutoff 上表现更好。

必须同时说清的三点：

1. **区间重叠，差值不显著**。pre-cutoff 只有 34 条，precision 区间宽 0.43。
   这批数据支持的结论是"**没有观察到记忆效应**"，不是"证明了不存在记忆效应"。
2. **两档难度不可比**。pre-cutoff 的 expected_findings 里 11/23（47.8%）是
   high/critical，post-cutoff 只有 7/142（4.9%）——pre 档难得多。这削弱了
   "post 更高 = 更没被污染"的直接读法，但也让结论更保守：模型在**更简单**的
   post 档上也只拿到 0.5634 recall。
3. **pre-cutoff 占比在两个文件里差一倍**。正样本 10/95（10.5%），
   clean 24/78（30.8%）。`clean_accuracy = 0.7308` 的分母里有近三成是模型
   可能记忆过的 PR，引用这个数时必须一并说明。

### 10.2 validation / holdout 分档

| 档 | cases | precision | recall | high_severity_recall |
|---|---|---|---|---|
| validation | 134 | 0.7640 [0.666, 0.840] | 0.5440 [0.457, 0.629] | 0.2778 [0.125, 0.509] |
| holdout | 39 | 0.7857 [0.605, 0.898] | 0.5500 [0.398, 0.693] | **—（无样本）** |

holdout 与 validation 接近，没有过拟合迹象。但有一条**必须写死的硬缺陷**：

> **holdout 的 40 条 expected_findings 里，high/critical 数量为 0。**

所以 `high_severity_recall` 在 holdout 上**永远算不出值**——这个指标目前
挂在 `_non_regressing` 的 protected 列表里，意味着它在 holdout 门禁上
**恒为"无从比较 → 放行"**。任何自称"通过 holdout 高危召回门禁"的说法
都是空的：那道门后面没有样本。

修复方向不是调门禁，是在 holdout 的 4 个仓库里补 high/critical 样本；
在补齐前，报告里不得声称高危能力经过 holdout 验证。

### 10.3 正负样本分档

| 档 | cases | precision | clean_accuracy |
|---|---|---|---|
| positive | 95 | 0.9783 [0.924, 0.994] | —（无 clean 样本） |
| clean | 78 | 0.0000 [0.000, 0.133] | 0.7308 [0.623, 0.817] |

这两个数**不能单独引用**，它们是同一个权衡的两端：

- positive 档的 precision 0.9783 之所以这么高，是因为分母里剔掉了负样本上
  的全部误报。这不是"精确率很高"，是"在保证有缺陷的前提下精确率很高"。
- clean 档的 precision 0.0000 不是 bug：负样本上任何 finding 都是误报，
  分子必然为 0。它等价于 `1 - clean_accuracy` 的另一种写法。

总体 precision 0.7692 才是可引用的数——它同时承担了两类样本。
