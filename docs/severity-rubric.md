# expected_findings 严重度/类别重标注 rubric v1

**先写 rubric 再标**。与 `docs/alert-rubric.md` 同一条纪律：先看数据再定
标准，会不自觉地把标准往"我已经相信的结论"上凑。本 rubric 定稿后不再
因为标注过程中遇到的具体样本而修改，覆盖不到的形态记入文末"待议形态"
进 v2，不追溯改 v1。

## 为什么要重标

原 `expected_findings` 的 `severity` / `defect_class` / `cwe` 三个字段
**不是人工评估的产物**，而是 `dataset_builder.DEFECT_CLASSES` 的八类正则
命中什么就打什么标，命中不了落进 `logic-boundary`(medium) 兜底。
`classify_defect_with_basis` 的 docstring 自己记录过：95 条里 63.2% 是
`fallback-default`。后果是 severity 这一维基本没有信息量：

| 原 severity | 条数 | 来源 |
|---|---|---|
| medium | 147 | 绝大多数是 logic-boundary 兜底的固定值 |
| high | 15 | 四类有规则背书的 + concurrency/auth-bypass 的弱命中 |
| critical | 3 | injection / auth-bypass 命中 |

D6 replay 首次算出 `high_severity_recall = 2/18 = 0.11`，抽查后发现分母
本身可疑（例如 `encode__httpx-pr-3109` 的 4 条 high，实际是
`MutableMapping` → `dict` 的类型注解契约变更）。**分母不可信时，这个比例
的绝对值不必讨论**——这与 alert-rubric 里"重测一致率是下限检验"是同一
性质的判断。

## 这个数字测的是什么，不测什么

测：**LLM-as-judge 在有特权上下文（人类真实修复补丁 + PR 标题）下，对
缺陷严重度与类别的判定**，以及它与原正则标签的分歧结构。

不测：严重度的客观真值。严重度本质上是业务影响判断（这个函数被谁调用、
故障半径多大），judge 拿不到调用图与部署上下文，因此：

- 重标结果标为 `label_source: "llm-judge-v1"`，与原 `"regex-class"`
  并存不覆盖，下游按来源区分置信度——与轨道 C 的
  `inferred-from-merge` / `manual-feedback` 分档是同一条原则。
- 声明"约等于人工标注"**必须先跑一次人工抽查校准**并报出一致率。
  未做校准前，不得在报告里把 `llm-judge-v1` 当 ground truth。

为什么仍然做：即便不能当真值，它也能回答一个更基础的问题——**原标签有
多大比例是站不住的**。这个分歧率本身就是数据集质量的直接指标。

## judge 能看到什么，不能看到什么

判定单元 = 一条 `expected_finding`。同一个 case 的多条一起判（共享 diff
上下文），但各自独立给标签。

**能看到**（这些构成"特权上下文"，是把 judge 抬到接近人工标注的关键）：

- 待审 diff（反转后的、含缺陷的代码）
- `fix_pr_title` —— 人类怎么描述这个缺陷
- `human_patch` —— 人类**真实的修复补丁**。这是最强的信号：修复动作的
  形态直接反映缺陷性质（加锁 → 并发；加校验 → 输入校验；改比较符 → 边界）
- `path` / `start_line` / `end_line` —— 判哪一处
- `repository` / `domain` —— 领域上下文

**不能看到**（工具层强制剥离，不靠 prompt 里写一句"请忽略"）：

- 原 `severity` / `defect_class` / `cwe`。看到就会锚定，分歧率必然虚低,
  那测的是"judge 能不能复读正则"。`blinded()` 主动剥掉这三个字段。
- D6 replay 的 reviewer 输出。judge 若看到被评测对象报了什么，会向它
  靠拢，等于让被测者参与制定尺子。

## 严重度判定标准

严重度按**影响与可达性**判，不按缺陷类别推导。这是与原实现最本质的
区别：原实现是"类别 → 固定 severity"的查表（`DefectClass.severity`），
同一类缺陷不论影响大小都拿同一个值。

判定顺序固定（顺序不固定则同一条按不同顺序问会得到不同答案）：

1. **无外部可见影响吗？** 纯类型注解/文档/日志文案/测试代码/死代码，
   或行为完全等价的重构 → `low`，停。
2. **未认证的外部输入能直接触达并造成越权、代码执行、数据泄露或
   静默数据损坏吗？** 是 → `critical`，停。
3. **有安全影响但需要前置条件**（需已认证、需特定配置、需竞态窗口），
   **或**核心路径的崩溃/挂死/错误结果 → `high`，停。
4. 否则 → `medium`。

### 各档的具体锚点

| 档 | 锚点 | 反例（常被误判进本档） |
|---|---|---|
| `critical` | RCE、认证绕过、凭据泄露、跨用户数据串号、大规模静默数据丢失 | "理论上可能被滥用"但无可达路径 → high |
| `high` | 已认证用户越权、TLS/证书校验缺失、核心请求路径 panic/hang、协议状态机错乱导致请求丢失 | 需要攻击者已控制服务端配置 → medium |
| `medium` | 非核心路径的错误结果、边界条件下的偏差、随时间累积的资源泄漏、罕见输入下的异常 | 有明确安全后果的 → high |
| `low` | 类型注解、日志、注释、命名、测试专属、行为等价重构 | 有任何用户可见行为变化的 → medium 起 |

### 明确不在本 rubric 扣分的事

- CWE 编号选得不够精确。CWE 有层级，兄弟节点之争（77/78/89/94/95）测的
  是"标注者选了哪个兄弟",不是缺陷性质。CWE 单独给字段，不影响 severity。
- 原标签是什么。judge 看不到，也不该反推。

## 类别判定

在原八类之外**允许**返回下列扩展类别。原因写在
`classify_defect_with_basis` 的 docstring 里：抽样读那 53 条判不出来的
标题，主体是大小写归一化、类型契约、输入校验、转义编码、协议状态机——
八类分类体系本身覆盖不住真实 bugfix 的主体。硬塞进八类等于让
`logic-boundary` 继续当垃圾桶。

原八类：`crypto-weak` `injection` `secret-exposure` `path-traversal`
`concurrency` `resource-leak` `auth-bypass` `logic-boundary`

扩展类：`input-validation` `contract-type` `state-machine`
`encoding-escaping` `error-handling` `api-misuse` `no-defect`

`no-defect` 是刻意加的逃生口：若 judge 在特权上下文下认为这一处
**根本不构成缺陷**（例如纯风格调整被采集器误判成 bugfix），必须能这么
说。禁止它就是逼 judge 在错样本上编一个类别出来——那正是原兜底机制的
错误。`no-defect` 条目单独报数，**不自动从数据集删除**：删数据要人工
确认，这与轨道 F"数据集是权威资产，保留人工闸"一致。

## 置信度

judge 每条给 `confidence` ∈ [0,1] 与一句 `basis`（判定依据，必须引用
diff 或 human_patch 里的具体内容，不接受"根据经验"）。

`confidence < 0.5` 的条目计入 `low_confidence_share` 单独报。它高就说明
即便有特权上下文也判不动，此时重标结果的可用性有限——同 `unlabelled_share`
的作用。

## 分歧率如何报

原标签与重标结果的对比，报三个数而不是一个：

- `severity_agreement` —— 四档完全相同的比例
- `severity_kappa` —— Cohen's κ，扣掉碰巧一致的期望。只报原始一致率会
  因为 147/165 都是 medium 而虚高：一个每次都猜 medium 的 judge 也能拿到
  约 0.79。复用 `alert_labelling.cohens_kappa`，不另写一份。
- `severity_drift` —— 混淆矩阵（原 → 新），看漂移**方向**。整体升级和
  整体降级对 `high_severity_recall` 的影响方向相反，一个标量看不出来。

## 人工校准（声明"约等于人工"的前置条件）

分层抽样：每个**新** severity 桶抽 ≥10 条（不足则全取），人工按本 rubric
独立判定，与 judge 结果算一致率与 κ。

- κ ≥ 0.6 且原始一致率 ≥ 0.85 → 可在报告中声明"LLM 标注，人工抽查
  校准一致率 x%"。**仍不得**简写成"人工标注数据集"。
- 未达标 → 只能报"LLM 重标，未通过人工校准"，且不得用于门禁。

抽样种子入库，保证可复现。人工轮**不得看到** judge 的 severity 与 basis
（同 alert-rubric 的盲测协议，工具层强制）。

## v1 实测结果（2026-09-05）

`python scripts/relabel_severity.py` 全量，165 条 finding / 95 条 case，
0 errored。结果在 `output/severity-relabel/relabel-v1.json`。

| 指标 | 值 |
|---|---|
| `severity_agreement` | 0.4061 |
| `severity_kappa` | −0.0019 |
| upgraded / downgraded / agreed | 39 / 59 / 67 |
| `high_or_above` | 18 → **44** |
| `no_defect_count` | 10 |
| `invalid_field_count` | 0 |
| `low_confidence_share` | 0.0 |

漂移矩阵（原 → 新）：

| 原 \ 新 | low | medium | high | critical |
|---|---|---|---|---|
| low (0) | 0 | 0 | 0 | 0 |
| medium (146) | 46 | 62 | 38 | 1 |
| high (15) | 4 | 6 | 5 | 0 |
| critical (3) | 0 | **3** | 0 | 0 |

### 这批数据能支持什么、不能支持什么

**能**：证伪原标签。κ ≈ 0 意味着两套标注**统计独立**——原 severity 与
judge 的判定之间没有可测的关联。这足以支撑"原 severity 不可用作
ground truth"这个结论。

**不能**：当新真值。κ ≈ 0 区分不了"judge 对、正则是噪声"和"两边都是
噪声"。未通过下面的人工校准前，`high_severity_recall` 在新标签下的
**绝对值不得报**。

### 两个反向验证（都做了）

1. **judge 是不是只是换了一张常量查表？** 原实现的根本错误是"类别 →
   固定 severity"。交叉制表 judge 的 severity × defect_class，类内
   severity 有实质分布：logic-boundary 纯度 0.66（n=79）、contract-type
   0.71（n=31）、concurrency 0.56（n=9）、input-validation 0.57（n=7）、
   error-handling 0.57（n=7）。查表在结构上做不出这个——原实现里
   concurrency 无论影响如何一律 high。纯度 1.0 的类（secret-exposure 4/4、
   api-misuse 5/5）n 太小，不构成反证。
2. **分歧是不是集中在一小撮坏样本上（可以剔掉）？** 按仓库看
   changed/total：httpx 12/16、paramiko 9/15、airflow 10/13、urllib3 10/12、
   dask 10/11、ansible 9/11、requests 9/11、celery 4/13、Pillow 2/11、
   django 3/10。**没有可切除的簇**——原标签是系统性不可靠，不是局部污染。

### 两条必须记住的坑

- **分母变了，跨版本不可比**。`high_severity_recall` 的分母 18 → 44。
  旧标签下的 0.2778 和新标签下的任何值**不是同一个量**，不得放在
  同一张趋势图里。
- **`confidence` 作为分诊信号是死的**。分布 0.9:66、0.95:39、0.8:26、
  0.85:13、0.7:8、1.0:5，最低 0.7，`low_confidence_share = 0.0`。
  原计划用它挑出"judge 也拿不准的"优先人工看——这个信号在当前数据上
  等于常量，抽样只能按新 severity 分层。

## 人工校准工具

```bash
python scripts/sample_severity_calibration.py --seed 20260905 --stamp 2026-09-05
```

按新 severity 分层抽样，产出 `output/severity-relabel/calibration-v1.json`。
v1 抽出 31 条：low/medium/high 各 10，critical 全部 1 条（不足 10，脚本
会打印警告——这一档报数时必须带 n）。

工具层保证的三件事：

- **剥离 judge 判定**：产出文件里不含 `severity_llm`/`basis`/`confidence`，
  标注者没法不小心瞄到。
- **同时剥离原标签**：原 severity 正是要证伪的对象，让人看见就是让人
  锚定到被告席上。
- **补上与 judge 完全一致的上下文**：同一份 `human_patch` + `diff` +
  `fix_pr_title`。多给会让一致率虚高（人拿着 judge 没有的信息判出一样，
  说明不了 judge 准），少给测的是另一个问题。

填 `severity_human`（判不动留 `null`，不要硬凑），然后：

```bash
python scripts/sample_severity_calibration.py --report
```

`meets_gate` 是三态：`true` / `false` / `null`（样本不足或 κ 无定义
——**没有结论**，不是未达标）。

## 待议形态

（标注过程中遇到、v1 规则覆盖不到的形态记在此处，进 v2）

- **原 critical 全部降到 medium（3/3）**。三条都是"理论上严重、但在
  该代码路径上不可达或已被上游拦住"。v1 rubric 的第二步（可达性）已经
  覆盖这个判断，但没有明确说"不可达是否直接压到 medium 还是按剩余
  影响判"——v2 需要写死，否则这一档全靠 judge 自由裁量。