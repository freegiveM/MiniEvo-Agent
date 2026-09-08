"""轨道 I：把提示词里"已验证的规则"变成可清点的条目。

## 缺口（已在代码里查证，不是照搬论文）

`_generate_candidate` 把整个亲本提示词交给生成器，拿回一个**完整重写**的
候选。而亲本是逐代累积的：v5 的提示词里含着 v2、v3、v4 各自学到的规则
（`auto_propose` 每轮把 `additions` 追加到 `base` 末尾的 "Learned
constraints:" 块里）。整体重写 + 逐代累积 = 迭代重写，正是
[ACE (arXiv:2510.04618)](https://arxiv.org/pdf/2510.04618) 说的
**context collapse**。

现有门禁挡不住，两处缝隙都真实存在：

- `safety_evaluate` 只数五个通用 token（`diff/severity/fix/test/json`）算
  `completeness`。它问的是"这还像不像一个 review 提示词"，**不是**"之前
  验证过的规则还在不在"。删掉 v2/v3/v4 学到的三条规则，completeness 仍是
  1.0，safety 门禁照过。
- holdout 门禁只**部分**兜住。纯粹丢失会掉分被拒——但拒绝理由写的是
  "a protected metric regressed"，不会说"你删掉了三条已验证规则"，于是同一个
  根因被反复重试。真正漏掉的是另一种：候选丢了两条旧规则、加了一条更强的
  新规则，**净分数上升**，门禁放行，三代积累悄悄少了两条，报告上完全看不出。

## 为什么清点必须是纯函数

不能让 LLM 来回答"你删了哪几条"——那是拿有 collapse 问题的东西去检测
collapse。这里只做确定性的字符串清点：`[focus-rule:X]` 标记本来就是
`auto_propose` 为了"machine-auditable in offline replay"才写进提示词的
（见 `evolution.py` 里那段注释），现在正好用上。

## 这个模块不声称什么

它清点的是**标记过的规则条目**，不是"提示词的全部语义"。一个候选可以在
不删任何 `[focus-rule:]` 标记的前提下，把某条规则的正文改写得失效——这个
函数看不出来。所以它是一道**必要**门禁，不是充分的：它能证明"确实删了
一条已验证规则"，不能证明"什么都没丢"。把它表述成后者就是又一个
`completeness` 式的假门禁。
"""
import re
from typing import Dict, List, Optional, Sequence

# 与 evolution.py / rejection_proof.py / evolution_proof.py 里的同一个模式。
# 刻意重复而不是 import：那三处各自有自己的用途（注入、审计、报告），
# 共享一个常量会让"改一处影响四处"，而这里要的只是"认得出这个标记"。
FOCUS_RULE = re.compile(r"\[focus-rule:([A-Z][A-Z0-9_-]{1,79})\]")

# `auto_propose` 追加学习条目时用的块头，见 evolution.py 里
# `base.rstrip() + "\n\nLearned constraints:\n- " + ...`。
LEARNED_HEADER = "Learned constraints:"

# 出处标记（见 `prompt_delta`）。条目正文的比对必须先把它们剥掉：
# 同一条规则在不同轮次被重新渲染时 `[src:]` 会变，若参与比对，`diff_rules`
# 会把"换了个出处"报成"删了一条规则"——一道会误报的门禁最终等于没有门禁。
PROVENANCE = re.compile(r"\s*\[(?:src|gates):[^\]]*\]")


def strip_provenance(text: str) -> str:
    """去掉 `[src:]` / `[gates:]` 标记，只留条目正文。"""
    return PROVENANCE.sub("", text or "").strip()


def extract_rule_ids(prompt: str) -> List[str]:
    """提示词里所有 `[focus-rule:X]` 标记，去重后按字典序。

    排序而不是保留出现顺序：这个列表会进报告并被逐次 diff，顺序随生成器
    措辞漂移会让 diff 全是噪声，真正的增删反而看不见。
    """
    return sorted(set(FOCUS_RULE.findall(prompt or "")))


def extract_learned_constraints(prompt: str) -> List[str]:
    """"Learned constraints:" 块里的条目正文。

    只取块内的 `- ` 开头行。块外的横线开头行是提示词本身的排版，把它们
    算成"已验证规则"会让门禁在第一次改排版时就误报，然后被当成噪声关掉
    ——一道会误报的门禁最终等于没有门禁。

    返回的正文已剥掉 `[src:]` / `[gates:]` 出处标记（见 `strip_provenance`）。
    """
    if not prompt:
        return []
    items: List[str] = []
    in_block = False
    for raw in prompt.splitlines():
        stripped = raw.strip()
        if stripped == LEARNED_HEADER:
            in_block = True
            continue
        if not in_block:
            continue
        if stripped.startswith("- "):
            items.append(strip_provenance(stripped[2:]))
            continue
        if stripped:
            # 块被非条目行打断——后面的内容不再属于这个块。
            in_block = False
    return items


def inventory(prompt: str) -> Dict[str, object]:
    """一份提示词的规则清单。"""
    constraints = extract_learned_constraints(prompt)
    return {
        "rule_ids": extract_rule_ids(prompt),
        "constraints": constraints,
        "constraint_count": len(constraints),
    }


def diff_rules(baseline: str, candidate: str) -> Dict[str, object]:
    """基线与候选之间的规则增删。

    `dropped` 是这道门禁的全部要点：候选相对基线**少掉**的已验证规则。
    新增不受限制——加规则不会侵蚀已积累的知识，那正是进化该做的事。
    """
    base_ids = set(extract_rule_ids(baseline))
    cand_ids = set(extract_rule_ids(candidate))
    base_items = extract_learned_constraints(baseline)
    cand_items = set(extract_learned_constraints(candidate))
    return {
        "dropped_rule_ids": sorted(base_ids - cand_ids),
        "added_rule_ids": sorted(cand_ids - base_ids),
        # 条目按正文精确比对。改写过的条目会同时出现在 dropped 和 added
        # 里——这是刻意的：门禁无法判断改写是等价还是削弱，交给人看。
        "dropped_constraints": [
            item for item in base_items if item not in cand_items
        ],
        "baseline_rule_ids": sorted(base_ids),
        "candidate_rule_ids": sorted(cand_ids),
    }


def retention_gate(
    baseline: str, candidate: str,
    allow_dropping: Optional[Sequence[str]] = None,
) -> Dict[str, object]:
    """删除一条已验证规则必须是**显式**动作。

    返回三态 `passed`：

    - `None` —— 基线里一条标记规则都没有，无从判断保留与否。**不是通过。**
      这与 `summarise_shadow_evidence` 分母为 0 返回 None、
      `_significance_report` 用三态是同一条纪律：一个恒为 True 的门禁在
      报告上和一道真门禁长得一模一样，而它什么都没挡住。调用方必须自己
      决定 None 怎么处理，不能顺手当 True。
    - `False` —— 候选删掉了基线里的已验证规则，且没有出现在
      `allow_dropping` 白名单里。
    - `True` —— 没有未声明的删除。

    `allow_dropping` 是那个"显式动作"：确认某条规则本身是错的（比如它来自
    一条后来被推翻的反馈）时，把 rule_id 显式列进来。默认空——删除不能作为
    重写的副产品静默发生。这与 `stage_shadow` 默认拒绝而非覆盖同源：
    **静默丢失证据比丢失本身更危险。**
    """
    delta = diff_rules(baseline, candidate)
    allowed = set(allow_dropping or ())
    undeclared = [
        rule_id for rule_id in delta["dropped_rule_ids"] if rule_id not in allowed
    ]
    if not delta["baseline_rule_ids"]:
        passed: Optional[bool] = None
        reason = (
            "the baseline carries no marked learned rules, so rule retention "
            "cannot be evaluated"
        )
    elif undeclared:
        passed = False
        reason = (
            "the candidate silently dropped %s learned rule(s) the baseline had "
            "(%s); dropping a verified rule must be an explicit, justified action "
            "rather than a side effect of rewriting the prompt"
            % (len(undeclared), ", ".join(undeclared))
        )
    else:
        passed = True
        reason = ""
    return {
        "passed": passed,
        "reason": reason,
        "undeclared_drops": undeclared,
        "declared_drops": sorted(allowed & set(delta["dropped_rule_ids"])),
        **delta,
    }


# --------------------------------------------------------------------------
# 结构化条目与增量 delta 合并（ACE 的 delta 机制，本模块的第二半）
#
# 上半截（inventory / diff_rules / retention_gate）是**事后清点**：候选已经
# 生成出来了，去数它丢了什么。它能发现 collapse，但发现的时候那次 LLM 调用
# 已经花掉了，而且它对"改写了正文但保留了 rule_id"无能为力（见模块开头的
# "这个模块不声称什么"）。
#
# 下半截是**事前构造**：已验证条目结构化落盘，生成器只能产出 delta，合成
# 提示词由纯函数完成。整体重写这条路径不再存在，所以 collapse 不是被拦下
# 而是无从发生。两半都要有——已有的 v1..vN 提示词是纯文本，只能靠上半截
# 清点；新走 delta 路径的才享受下半截的保证。
# --------------------------------------------------------------------------

# delta 的三种操作。`replace` 与 `drop` 分开：改写一条规则（正文更强了）和
# 撤掉一条规则（当初那条反馈是错的）是两件不同的事，后者必须给理由。
OP_ADD = "add"
OP_REPLACE = "replace"
OP_DROP = "drop"
OPS = (OP_ADD, OP_REPLACE, OP_DROP)


def make_entry(
    rule_id: str, text: str, run_id: str = "",
    gates_passed: Optional[Sequence[str]] = None,
) -> Dict[str, object]:
    """一条结构化的已验证规则。

    `run_id` 与 `gates_passed` 是计划第 3 节要求的"来源 run_id 和它当初
    通过的门禁"。它们不是装饰：一条规则值不值得保留，取决于它当初是怎么
    被验证的。一条只通过了 safety 门禁的规则和一条通过了 holdout
    non-regression 的规则，在"该不该允许删除"上不是同一个分量——而如果不
    落盘，事后再也无从区分。

    刻意**不**记时间戳：这个结构会进提示词并被逐次 diff，一个每轮都变的
    字段会让 diff 全是噪声（与 `extract_rule_ids` 排序同一个理由）。轮次
    信息由 `run_id` 承载，它指回 `evolution_runs` 那一行，时间在那里。
    """
    rule_id = str(rule_id or "").strip()
    if not FOCUS_RULE.fullmatch("[focus-rule:%s]" % rule_id):
        raise ValueError(
            "rule_id %r is not a well-formed rule identifier; the same pattern "
            "gates FEEDBACK_RULE_ID, so accepting a loose id here would inject "
            "an unexecutable marker into the prompt" % rule_id
        )
    body = strip_provenance(text)
    if not body:
        raise ValueError("a learned rule entry needs non-empty text")
    return {
        "rule_id": rule_id,
        "text": body,
        "run_id": str(run_id or ""),
        "gates_passed": sorted(gates_passed or ()),
    }


def render_entry(entry: Dict[str, object]) -> str:
    """一条条目渲染成提示词里的一行。

    出处以 `[src:]` / `[gates:]` 标记跟在正文后面，与 `[focus-rule:]`
    同一个形态——LLM 读得懂，离线回放也数得出来。`strip_provenance` 负责
    在比对前把它们剥掉，所以换了出处不会被报成删了规则。
    """
    line = str(entry["text"]).strip()
    if "[focus-rule:%s]" % entry["rule_id"] not in line:
        line = "%s [focus-rule:%s]." % (line.rstrip("."), entry["rule_id"])
    if entry.get("run_id"):
        line += " [src:%s]" % entry["run_id"]
    if entry.get("gates_passed"):
        line += " [gates:%s]" % ",".join(entry["gates_passed"])
    return line


def compose_prompt(
    body: str, entries: Sequence[Dict[str, object]],
    unstructured: Sequence[str] = (),
) -> str:
    """提示词主体 + 一个 "Learned constraints:" 块。

    **只产出一个块**，而累积式的 `auto_propose` 每轮追加一个新块（真实的
    v3 提示词有两个，见 `tests/test_prompt_rules.py` 里那条测试）。多块本身
    不是错的——`extract_learned_constraints` 认得出全部——但它意味着提示词
    的形态取决于走过多少轮，而 delta 路径要的是"同一批条目永远合成同一个
    字符串"，否则候选与基线的 diff 里会混进排版差异。

    条目按 rule_id 排序，同样为了这个确定性。

    `unstructured` 是没有 rule_id 的通用指令（`auto_propose` 那四条
    "Avoid style-only findings…" 之类）。它们**保持传入顺序**、排在带标记的
    条目之前：它们没有稳定身份，排序只能按正文，而正文一改就会在 diff 里
    表现成"删一条加一条"。参数存在的唯一理由是它们不能被丢掉——
    `entries_from_prompt` 把它们单独摘出来，合成时必须原样放回去。
    """
    body = (body or "").rstrip()
    lines = [text.strip() for text in unstructured if text and text.strip()]
    lines.extend(render_entry(entry) for entry in sort_entries(entries))
    if not lines:
        return body
    return body + "\n\n" + LEARNED_HEADER + "\n- " + "\n- ".join(lines)


def sort_entries(entries: Sequence[Dict[str, object]]) -> List[Dict[str, object]]:
    return sorted(entries, key=lambda entry: str(entry["rule_id"]))


def entries_from_prompt(prompt: str) -> Dict[str, object]:
    """把一个既有的纯文本提示词抬举成结构化条目 + 主体。

    没有这一步 delta 路径就永远起不了步：现存所有版本都是纯文本，而
    `apply_delta` 需要一个条目集合作为起点。

    返回 `{body, entries, unstructured}`。`unstructured` 是块里那些**没有
    `[focus-rule:]` 标记**的条目——`auto_propose` 的四条通用 directive
    （"Avoid style-only findings…" 之类）就属于这一类。它们不进 `entries`：
    没有 rule_id 就没有稳定身份，塞进去只能按正文当 key，而正文一改就变成
    "删一条加一条"。**但也不能丢**，所以原样返回给调用方，由调用方决定
    放回主体还是别的处理。静默丢掉它们就是又一次 collapse，只不过发生在
    我们自己的代码里而不是 LLM 里。
    """
    prompt = prompt or ""
    entries: List[Dict[str, object]] = []
    unstructured: List[str] = []
    for item in extract_learned_constraints(prompt):
        found = FOCUS_RULE.search(item)
        if found:
            entries.append(make_entry(found.group(1), item))
        else:
            unstructured.append(item)
    # 主体 = 第一个 "Learned constraints:" 块之前的部分。
    head = prompt.split("\n" + LEARNED_HEADER)[0]
    if head.strip() == prompt.strip():
        head = prompt.split(LEARNED_HEADER)[0]
    return {
        "body": head.rstrip(),
        "entries": sort_entries(entries),
        "unstructured": unstructured,
    }


def validate_delta(delta: Sequence[Dict[str, object]]) -> List[str]:
    """delta 自身的形状检查，返回问题清单（空 = 合法）。

    这一层挡的是**生成器给了个说不通的 delta**，与 collapse 是两回事，但
    不挡的后果一样严重：一个 op 写错的 delta 若被 `apply_delta` 宽容地跳过，
    表现就是"这一轮学到的规则静默没进去"——和 collapse 一模一样的症状，
    而且更难查，因为没有任何一条规则被删。所以宁可报错。
    """
    problems: List[str] = []
    seen = set()
    for index, item in enumerate(delta or ()):
        if not isinstance(item, dict):
            problems.append("delta[%d] is not an object" % index)
            continue
        op = item.get("op")
        rule_id = str(item.get("rule_id") or "").strip()
        where = "delta[%d] (%s %s)" % (index, op, rule_id or "?")
        if op not in OPS:
            problems.append("%s: op must be one of %s" % (where, ", ".join(OPS)))
        if not FOCUS_RULE.fullmatch("[focus-rule:%s]" % rule_id):
            problems.append("%s: rule_id is not a well-formed identifier" % where)
        elif rule_id in seen:
            # 同一条规则在一个 delta 里出现两次，结果取决于应用顺序——
            # 那正是"确定性合并"要排除的东西。
            problems.append("%s: rule_id appears more than once in one delta" % where)
        else:
            seen.add(rule_id)
        if op in (OP_ADD, OP_REPLACE) and not strip_provenance(str(item.get("text") or "")):
            problems.append("%s: %s needs non-empty text" % (where, op))
        if op == OP_DROP and not str(item.get("reason") or "").strip():
            # 删除必须给理由。这与 `retention_gate` 的 `allow_dropping`
            # 是同一条纪律的两端：那边挡的是"重写的副产品"，这边挡的是
            # "delta 里一句话不说就删掉"。
            problems.append("%s: dropping a verified rule requires a reason" % where)
    return problems


def apply_delta(
    entries: Sequence[Dict[str, object]], delta: Sequence[Dict[str, object]],
) -> Dict[str, object]:
    """把一个 delta 确定性地合并进已验证条目集合。

    **纯函数，不经 LLM。** 这是 ACE delta 机制里唯一真正重要的一条：让
    LLM 决定"改什么"，但让代码决定"改完之后集合是什么"。反过来（让 LLM
    输出合并后的完整提示词）就是 `_generate_candidate` 现在的做法，也就是
    collapse 的来源。

    返回 `{entries, applied, rejected, dropped}`。非法 delta **不合并、
    不部分合并**：`validate_delta` 有一条问题就整个拒绝，`entries` 原样
    返回。部分合并会产出一个"看起来正常但少了一条"的条目集，那是最难查的
    一类缺陷。
    """
    problems = validate_delta(delta)
    if problems:
        return {
            "entries": sort_entries(entries),
            "applied": [],
            "rejected": problems,
            "dropped": [],
        }
    merged = {str(entry["rule_id"]): dict(entry) for entry in entries}
    applied: List[str] = []
    dropped: List[Dict[str, object]] = []
    rejected: List[str] = []
    for item in delta:
        op = item["op"]
        rule_id = str(item["rule_id"]).strip()
        if op == OP_ADD:
            if rule_id in merged:
                # add 一条已存在的规则：生成器要么没看清基线，要么真想改写。
                # 不猜——猜错的两种后果（静默覆盖 / 静默忽略）都是丢信息。
                rejected.append(
                    "add %s: the rule already exists; use %s to change its text"
                    % (rule_id, OP_REPLACE)
                )
                continue
            merged[rule_id] = make_entry(
                rule_id, str(item["text"]), str(item.get("run_id") or ""),
                item.get("gates_passed"),
            )
            applied.append("%s %s" % (op, rule_id))
        elif op == OP_REPLACE:
            if rule_id not in merged:
                rejected.append(
                    "replace %s: no such rule in the current set; use %s"
                    % (rule_id, OP_ADD)
                )
                continue
            previous = merged[rule_id]
            merged[rule_id] = make_entry(
                rule_id, str(item["text"]),
                str(item.get("run_id") or previous.get("run_id") or ""),
                item.get("gates_passed") or previous.get("gates_passed"),
            )
            applied.append("%s %s" % (op, rule_id))
        else:
            if rule_id not in merged:
                rejected.append("drop %s: no such rule in the current set" % rule_id)
                continue
            removed = merged.pop(rule_id)
            dropped.append({
                "rule_id": rule_id,
                "reason": str(item["reason"]).strip(),
                # 被删条目的正文与出处一并留在报告里。只记 rule_id 的话,
                # 事后想复核"这条当初通过了 holdout 门禁，真该删吗"就没了
                # 依据——而那是唯一能判断这次删除对不对的信息。
                "text": removed["text"],
                "run_id": removed.get("run_id", ""),
                "gates_passed": removed.get("gates_passed", []),
            })
            applied.append("%s %s" % (op, rule_id))
    return {
        "entries": sort_entries(merged.values()),
        "applied": applied,
        "rejected": rejected,
        "dropped": dropped,
    }