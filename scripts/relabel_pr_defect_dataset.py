#!/usr/bin/env python3
"""用 LLM 重新给 real-pr 数据集打标，逐条落盘，可断点续修。

## 为什么要重打标

`evoagent/dataset_builder.py` 的 `_classify()` 在代码模式和标题词都匹配不上时兜底
返回 `logic-boundary` / CWE-193（`dataset_builder.py:377`）。该函数自己的 docstring
记录了实测兜底率 61%，全量 95 条 positive 的标注分布印证了这一点：144 个 finding
里 CWE-193 占 89%，其余六类合计 21 个。

后果不是"标注粒度粗"，是**标注错**。抽查三条：

    django-21803    get_names_to_join() 换成 name.split()   → 标 CWE-193
    bandit-1333     删掉 isinstance(x.value, str) 类型检查   → 标 CWE-193
    airflow-72203   docstring 里去掉两个反引号               → 标 CWE-193

第三条是纯文档格式改动，被标成了"差一错误"。四臂消融跑出 recall≈0，模型说
"这个 docstring 改动没问题"是对的，却被记成漏报——这个 recall 衡量的是标注质量，
不是 Agent 能力。原作者的处理是不报 per-class 指标、让硬约束告警一直响；那对当时
是诚实的，但要让 recall 可信就必须真的把标注修对。

## 为什么用 LLM 打标不算作弊

打标器看的是 `human_patch`（人类真实修复补丁）+ PR 标题 + 关联 issue，这些**就是
ground truth 的来源**，不是待审信息。被评测的 reviewer 只看反转后的 `diff`，永远
看不到 `human_patch`。两者信息集严格分离，所以这里让 LLM 看全部答案是正当的——它
在做的是"读人类修复，判断修的是什么类型的缺陷"，跟人工标注同一件事。

真正要防的是反过来：把打标结果里的自然语言解释泄漏进 reviewer 的提示词。所以输出
只保留 cwe / defect_class / severity / is_defect 这些结构化字段，`rationale` 单独
写进报告文件供人工抽查，不进数据集。

## 为什么 prompt_version 必须进检查点的 key

`output/ablation-pilot/checkpoint.jsonl` 的 key 只含 `(arm, case_id, diff)`，不含
代码版本。结果是改了 prompt 或修了 bug 之后旧缓存不失效，跑出来的东西是新旧混合
的——这正是上一批数据的隐患。这里把 `PROMPT_VERSION` 放进哈希：打标口径一改，
缓存自动全部失效，不会悄悄复用对不上号的标注。改口径时**必须**同步改这个常量。

## 不覆盖 real-pr-v1.jsonl

原数据集是权威输入，重打标写到独立的 `-relabelled.jsonl`。这样两份可以并排 diff，
也能在打标口径出问题时随时退回，不需要重新爬 PR。
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import time
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

# 改动下面任何一处（类别表、提示词、输出字段口径）都必须同时改这个版本号，
# 否则旧检查点会被当成新口径的结果复用。
PROMPT_VERSION = "relabel-v2"

# 十二类，前八类对齐 dataset_builder.DEFECT_CLASSES，后四类是 v2 新增。
#
# v1 用八类跑过一轮，实测 73 条真缺陷里 53 条只能落 other（CWE-noinfo）。
# 而 category 档在 truth 无族时退回严格字符串相等，导致一个定位完全正确的
# reviewer 在该档只能拿 12%——衡量的是标注体系的窟窿，不是 reviewer 能力。
# 后四类补的正是抽样读出来的真实主体：输入校验、类型契约、编码转义、协议
# 状态机。每个 CWE 编号都在 evaluation_harness.CWE_FAMILY 里有对应族，
# 两边必须同步改，否则新类别照样落不到族上。
#
# other 保留，但含义收窄成"连十二类也归不进去"。它仍然映射到 CWE-noinfo
# 且刻意不给族——"我不知道"不该算作 category 命中。
TAXONOMY = {
    "crypto-weak": ("CWE-328", "high"),
    "injection": ("CWE-78", "critical"),
    "secret-exposure": ("CWE-798", "high"),
    "path-traversal": ("CWE-22", "high"),
    "concurrency": ("CWE-362", "high"),
    "resource-leak": ("CWE-772", "medium"),
    "auth-bypass": ("CWE-285", "critical"),
    "logic-boundary": ("CWE-193", "medium"),
    "input-validation": ("CWE-1284", "medium"),
    "type-contract": ("CWE-704", "medium"),
    "encoding": ("CWE-116", "medium"),
    "protocol-state": ("CWE-372", "medium"),
    "other": ("CWE-noinfo", "medium"),
}

# non_defect 的取值刻意分得细：报告里要能看出"被剔掉的到底是什么"。
# 如果剔除量大而且集中在 docs/format，说明数据采集阶段的 bugfix 判定太松，
# 那是 collect_reverted_fix_dataset.py 该修的事，不是打标能补的。
NON_DEFECT_KINDS = (
    "docs-only", "format-only", "refactor-only", "test-only",
    "feature-or-behaviour-change", "dependency-bump", "unclear",
)

SYSTEM_PROMPT = """You label a dataset of historical bug-fix pull requests.

You are shown the MERGED HUMAN FIX for a real pull request. Your job is to decide
what kind of defect that fix repaired, so an evaluation harness can score
reviewers that see only the reverted (re-introduced-bug) diff.

Answer two questions.

1. Is this genuinely a DEFECT FIX? Many merged PRs are not. Answer false for:
   docstring/comment wording, code formatting, pure refactors with no behaviour
   change, test-only changes, new features, dependency bumps. A defect fix
   changes runtime behaviour in a way that repairs incorrect behaviour.

2. If it IS a defect fix, which class? Choose exactly one:

   crypto-weak       weak/misused cryptography, bad randomness, TLS verification
   injection         SQL/command/code/template injection, unsafe deserialization
   secret-exposure   credentials or sensitive data leaked or logged
   path-traversal    unsanitised paths escaping their intended root
   concurrency       races, deadlocks, unsafe shared state, shutdown ordering
   resource-leak     unreleased handles/memory/connections, unbounded growth
   auth-bypass       missing or incorrect authorisation/authentication checks
   logic-boundary    off-by-one, wrong comparison operator, boundary arithmetic
   input-validation  accepting input that should be rejected (or the reverse):
                     substring instead of token match, missing range/enum check
   type-contract     wrong type assumptions, bad coercion, None/optional misuse,
                     signature or return-contract violations
   encoding          escaping, charset, case-normalisation, serialisation format
   protocol-state    wrong state transition or protocol/spec conformance
                     (HTTP/WebSocket/TLS semantics, reserved values, lifecycle)
   other             a real defect that fits none of the twelve

   Pick the class describing the ROOT CAUSE the fix addresses, not the symptom.
   Do NOT default to logic-boundary — reserve it for genuine off-by-one,
   boundary, or comparison-operator errors. Use "other" honestly rather than
   forcing a poor fit; "other" is a valid and useful answer.

Return JSON only:
{"is_defect": bool, "non_defect_kind": string|null, "defect_class": string|null,
 "severity": "low"|"medium"|"high"|"critical"|null, "rationale": string}

non_defect_kind is required when is_defect is false; one of:
docs-only, format-only, refactor-only, test-only, feature-or-behaviour-change,
dependency-bump, unclear. Keep rationale under 40 words."""


class LabelCheckpoint:
    """(case_id, human_patch, PROMPT_VERSION) -> 打标结果。

    只缓存成功结果。一次瞬时的 API 失败被当成永久标注，比多花一次钱贵得多。
    """

    def __init__(self, path: Path):
        self.path = path
        self.cache: dict = {}
        self.hits = 0
        self.misses = 0
        if path.exists():
            with path.open(encoding="utf-8") as handle:
                for line in handle:
                    line = line.strip()
                    if line:
                        record = json.loads(line)
                        self.cache[record["key"]] = record

    @staticmethod
    def key(case_id: str, patch: str) -> str:
        digest = hashlib.sha256()
        for part in (PROMPT_VERSION, case_id, patch):
            digest.update(part.encode("utf-8"))
            digest.update(b"\x00")
        return digest.hexdigest()

    def get(self, key: str):
        if key in self.cache:
            self.hits += 1
            return self.cache[key]["label"]
        return None

    def put(self, key: str, case_id: str, label: dict) -> None:
        self.misses += 1
        record = {"key": key, "case_id": case_id, "label": label}
        self.cache[key] = record
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(record, ensure_ascii=False) + "\n")
            handle.flush()
            os.fsync(handle.fileno())


def build_user_prompt(case: dict, max_chars: int) -> str:
    parts = [
        "Repository: %s" % case.get("repository", ""),
        "Pull request title: %s" % case.get("fix_pr_title", ""),
        "Label provenance: %s" % case.get("label_provenance", ""),
        "",
        "MERGED HUMAN FIX (this repaired the defect):",
        (case.get("human_patch") or "")[:max_chars],
    ]
    return "\n".join(parts)


def normalise(raw: dict) -> dict:
    """把模型输出收敛到固定字段，非法值一律落到可审计的兜底而不是猜。"""
    is_defect = bool(raw.get("is_defect"))
    rationale = str(raw.get("rationale") or "")[:400]
    if not is_defect:
        kind = str(raw.get("non_defect_kind") or "unclear")
        if kind not in NON_DEFECT_KINDS:
            kind = "unclear"
        return {
            "is_defect": False, "non_defect_kind": kind,
            "defect_class": None, "cwe": None, "severity": None,
            "rationale": rationale,
        }
    name = str(raw.get("defect_class") or "").strip().lower()
    if name not in TAXONOMY:
        name = "other"
    cwe, default_severity = TAXONOMY[name]
    severity = str(raw.get("severity") or "").strip().lower()
    if severity not in ("low", "medium", "high", "critical"):
        severity = default_severity
    return {
        "is_defect": True, "non_defect_kind": None,
        "defect_class": name, "cwe": cwe, "severity": severity,
        "rationale": rationale,
    }


def relabel_case(case: dict, client, checkpoint: LabelCheckpoint,
                 max_chars: int, progress) -> dict:
    patch = case.get("human_patch") or case.get("diff") or ""
    key = checkpoint.key(str(case["id"]), patch)
    cached = checkpoint.get(key)
    if cached is not None:
        progress(case["id"], "cached", cached, 0.0)
        return cached
    started = time.monotonic()
    raw = client.complete_json(
        "dataset-relabeller", SYSTEM_PROMPT,
        # 16000 而不是 4000：这是推理模型，max_tokens 同时封顶 reasoning +
        # content。实测 4000 时有 4 条把全部预算烧在推理上（reasoning_tokens=4000,
        # content_chars=0），报成"hit the token budget"。判类别本身只需要几十个
        # token 的输出，瓶颈全在推理，所以直接给足。
        build_user_prompt(case, max_chars), max_tokens=16000,
    )
    label = normalise(raw)
    checkpoint.put(key, str(case["id"]), label)
    progress(case["id"], "fresh", label, time.monotonic() - started)
    return label


def apply_label(case: dict, label: dict) -> dict:
    """把新标注写回 case。

    行号原样保留：`expected_findings` 的 start_line/end_line 是从 diff 的新增行
    算出来的，与类别判定无关，重算只会引入新的对齐错误。这里只改类别相关字段。
    """
    updated = dict(case)
    updated["defect_class"] = label["defect_class"]
    updated["defect_class_basis"] = "llm-relabel:" + PROMPT_VERSION
    findings = []
    for item in case.get("expected_findings") or []:
        value = dict(item)
        value["cwe"] = label["cwe"]
        value["defect_class"] = label["defect_class"]
        value["severity"] = label["severity"]
        findings.append(value)
    updated["expected_findings"] = findings
    return updated


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--dataset", default=str(ROOT / "datasets" / "real-pr-v1.jsonl"),
        help="原数据集，只读，不覆盖",
    )
    parser.add_argument("--base-url", default=os.getenv("EVOAGENT_LLM_BASE_URL", ""))
    parser.add_argument("--api-key", default=os.getenv("EVOAGENT_LLM_API_KEY", ""))
    parser.add_argument("--model", default=os.getenv("EVOAGENT_LLM_MODEL", ""))
    parser.add_argument("--provider", default=os.getenv("EVOAGENT_LLM_PROVIDER", "custom"))
    parser.add_argument("--timeout", type=int, default=180)
    parser.add_argument("--max-patch-chars", type=int, default=6000)
    parser.add_argument(
        "--include-other", action="store_true",
        help="把 defect_class=other 的样本也写进输出（默认保留，剔除用 --drop-other）",
    )
    parser.add_argument(
        "--drop-other", action="store_true",
        help="剔除判不出类别的样本。慎用：它们是真缺陷，剔掉会让数据集偏向易分类的缺陷",
    )
    parser.add_argument(
        "--out-dir", default=str(ROOT / "output" / "relabel"),
        help="checkpoint.jsonl 和 report.json 写在这里",
    )
    parser.add_argument(
        "--out-dataset", default=str(ROOT / "datasets" / "real-pr-v1-relabelled.jsonl"),
    )
    parser.add_argument("--limit", type=int, default=0, help="只处理前 N 条，用于试跑")
    args = parser.parse_args()
    if not args.base_url or not args.api_key or not args.model:
        parser.error("--base-url, --api-key and --model are required")

    from evoagent.evaluation_harness import load_jsonl
    from evoagent.llm import JsonChatClient

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    checkpoint = LabelCheckpoint(out_dir / "checkpoint.jsonl")
    print(json.dumps({
        "prompt_version": PROMPT_VERSION,
        "checkpoint": str(out_dir / "checkpoint.jsonl"),
        "preloaded": len(checkpoint.cache),
    }, ensure_ascii=False), flush=True)

    counters = {"n": 0}

    def progress(case_id, kind, label, elapsed):
        counters["n"] += 1
        print(json.dumps({
            "n": counters["n"], "case": case_id, "kind": kind,
            "is_defect": label["is_defect"],
            "class": label["defect_class"] or label["non_defect_kind"],
            "elapsed_ms": int(elapsed * 1000),
        }, ensure_ascii=False), flush=True)

    client = JsonChatClient(
        args.base_url, args.api_key, args.model,
        provider=args.provider, timeout=args.timeout,
    )
    cases = load_jsonl(args.dataset)
    if args.limit:
        cases = cases[: args.limit]

    kept, dropped, failures = [], [], []
    class_counts, non_defect_counts = Counter(), Counter()
    audit = []
    for case in cases:
        try:
            label = relabel_case(case, client, checkpoint, args.max_patch_chars, progress)
        except Exception as exc:  # 不落检查点，下次原样重跑这一条
            failures.append({"case": case["id"], "error": str(exc)[:300]})
            print(json.dumps({
                "case": case["id"], "kind": "error", "error": str(exc)[:200],
            }, ensure_ascii=False), flush=True)
            continue
        audit.append({
            "case": case["id"],
            "old_class": case.get("defect_class"),
            "old_basis": case.get("defect_class_basis"),
            "new_class": label["defect_class"] or ("NON-DEFECT:" + str(label["non_defect_kind"])),
            "rationale": label["rationale"],
            "fix_pr_url": case.get("fix_pr_url"),
        })
        if not label["is_defect"]:
            non_defect_counts[label["non_defect_kind"]] += 1
            dropped.append({"case": case["id"], "reason": label["non_defect_kind"]})
            continue
        if label["defect_class"] == "other" and args.drop_other:
            class_counts["other(dropped)"] += 1
            dropped.append({"case": case["id"], "reason": "class-other"})
            continue
        class_counts[label["defect_class"]] += 1
        kept.append(apply_label(case, label))

    out_dataset = Path(args.out_dataset)
    out_dataset.parent.mkdir(parents=True, exist_ok=True)
    with out_dataset.open("w", encoding="utf-8", newline="\n") as handle:
        for case in kept:
            handle.write(json.dumps(case, ensure_ascii=False) + "\n")

    old_counts = Counter(
        item.get("cwe") for case in cases
        for item in case.get("expected_findings") or []
    )
    report = {
        "prompt_version": PROMPT_VERSION,
        "source_dataset": args.dataset,
        "out_dataset": str(out_dataset),
        "input_cases": len(cases),
        "kept_cases": len(kept),
        "dropped_cases": len(dropped),
        "failed_cases": failures,
        "old_cwe_distribution": dict(old_counts),
        "new_class_distribution": dict(class_counts),
        "non_defect_distribution": dict(non_defect_counts),
        "dropped": dropped,
        "audit": audit,
        "checkpoint_hits": checkpoint.hits,
        "checkpoint_misses": checkpoint.misses,
    }
    report_path = out_dir / "report.json"
    with report_path.open("w", encoding="utf-8", newline="\n") as handle:
        json.dump(report, handle, ensure_ascii=False, indent=2, sort_keys=True)
        handle.write("\n")

    print(json.dumps({
        "out_dataset": str(out_dataset), "report": str(report_path),
        "input": len(cases), "kept": len(kept), "dropped": len(dropped),
        "failed": len(failures),
        "new_class_distribution": dict(class_counts),
        "non_defect_distribution": dict(non_defect_counts),
        "checkpoint_hits": checkpoint.hits, "checkpoint_misses": checkpoint.misses,
    }, ensure_ascii=False, indent=2), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
