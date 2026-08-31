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

80–100 个 PR，14–18 个仓库。
仓库不相交切分 Validation / Holdout（约 11 : 5 仓库，约 70% : 30%）。

**仓库不相交是硬约束**：同仓库的 PR 共享代码风格、目录结构和惯用法，
切在 PR 级别会让 holdout 泄漏。

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
