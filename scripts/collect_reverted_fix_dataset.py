"""Collect merged bugfix PRs and reverse them into a review-evaluation dataset.

    export GITHUB_TOKEN=...
    python scripts/collect_reverted_fix_dataset.py \
        --repos datasets/repos.yaml \
        --output datasets/real-pr-v1.jsonl

设计见 datasets/README.md。全部判定逻辑在 evoagent/dataset_builder.py（有 38 个
离线单测）；本脚本只负责翻页、限流、缓存和落盘——这样"一个 case 长什么样"
的规则不依赖网络就能验证。

与既有 scripts/import_github_pr_dataset.py 的关系（为什么新写而不是改）：
那个脚本要求**先有人工标注的 manifest**（"Public PR content alone is not
ground truth, so unlabelled records are intentionally rejected"），它解决的是
"已经标好了，把 diff 抓下来"。本脚本解决的是上游问题：标注从哪来。
反转构造让标注来自 fix PR 本身，不需要人工先标 100 条。两者互补，都保留。

限流策略（GitHub REST，认证后 5000 次/小时）：
- 每仓库 1 次 list（每页 100）+ 每个候选 PR 1 次 diff 抓取。
  16 仓库 × ~3 页 + ~600 候选 ≈ 650 次请求，远低于配额；瓶颈是耗时不是配额。
- 读 X-RateLimit-Remaining，低于阈值时按 X-RateLimit-Reset 睡到重置。
- 抓下来的 diff 写本地缓存：--resume 二次运行零请求，便于反复调筛选规则
  而不重新耗配额。这是本脚本最实用的一点。
"""
import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone


ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from evoagent.dataset_builder import (  # noqa: E402
    MAX_FALLBACK_SHARE,
    CaseRejected,
    PullRequest,
    build_case,
    build_clean_case,
    diff_fingerprint,
    screen_title,
    screen_title_for_clean,
    summarise,
)
from evoagent.evaluation_harness import validate_case  # noqa: E402

API = "https://api.github.com"
USER_AGENT = "evoagent-reverted-fix-collector"
RATE_FLOOR = 50          # 剩余配额低于此值就等重置，留余量给并发的其他调用
PAGE_SIZE = 100
# 未认证配额是 60/小时。留 10 次余量给手工排查，别把配额刚好用干。
PILOT_BUDGET = 50


class BudgetExhausted(Exception):
    """请求预算用尽。pilot 模式用它干净地收尾，而不是让配额在半路报 403。"""


class GitHub:
    def __init__(
        self, token: str, cache_dir: str, verbose: bool = True,
        max_requests: int = 0, rate_floor: int = RATE_FLOOR,
    ) -> None:
        self.token = token
        self.cache_dir = cache_dir
        self.verbose = verbose
        self.requests = 0
        self.cache_hits = 0
        self.max_requests = max_requests        # 0 = 不限
        # 为什么 floor 要可调：未认证上限就是 60，固定 floor=50 会让第 10 次
        # 请求就触发"配额将尽"而睡到下个小时——pilot 永远跑不完。pilot 有自己
        # 的硬上限，floor 的职责（给其他调用方留余量）已由硬上限承担。
        self.rate_floor = rate_floor
        os.makedirs(cache_dir, exist_ok=True)

    def _headers(self, accept: str) -> dict:
        headers = {
            "Accept": accept,
            "User-Agent": USER_AGENT,
            "X-GitHub-Api-Version": "2022-11-28",
        }
        if self.token:
            headers["Authorization"] = "Bearer " + self.token
        return headers

    def _get(self, url: str, accept: str) -> str:
        # 预算检查放在发请求之前：超了就一次都不发。放在之后就等于允许超一次。
        if self.max_requests and self.requests >= self.max_requests:
            raise BudgetExhausted("used %d requests" % self.requests)
        request = urllib.request.Request(url, headers=self._headers(accept))
        for attempt in range(4):
            try:
                with urllib.request.urlopen(request, timeout=90) as response:
                    self.requests += 1
                    self._respect_rate_limit(response.headers)
                    return response.read().decode("utf-8", errors="replace")
            except urllib.error.HTTPError as exc:
                # 403/429 且带 Retry-After 或配额耗尽 → 等待重试，不是错误。
                if exc.code in (403, 429):
                    wait = self._retry_delay(exc.headers, attempt)
                    self._log("rate limited (HTTP %d), sleeping %ds" % (exc.code, wait))
                    time.sleep(wait)
                    continue
                if exc.code in (404, 406, 451):
                    # 仓库改名/PR 被删/DMCA 下架：跳过而不是中断整轮采集。406
                    # 是实测踩到的：个别 PR（如超大 diff）在 diff media type 上
                    # 返回 Not Acceptable，是这一个资源的问题，不是请求本身错了，
                    # 跳过它不该让已经跑了几百次请求的一整轮采集前功尽弃。
                    raise LookupError("HTTP %d for %s" % (exc.code, url)) from exc
                if 500 <= exc.code < 600 and attempt < 3:
                    time.sleep(2 ** attempt)
                    continue
                raise RuntimeError("HTTP %d for %s" % (exc.code, url)) from exc
            except (urllib.error.URLError, TimeoutError) as exc:
                if attempt < 3:
                    time.sleep(2 ** attempt)
                    continue
                raise RuntimeError("network failure for %s: %s" % (url, exc)) from exc
        raise RuntimeError("gave up on %s" % url)

    def _retry_delay(self, headers, attempt: int) -> int:
        after = headers.get("Retry-After")
        if after and str(after).isdigit():
            return min(int(after), 300)
        reset = headers.get("X-RateLimit-Reset")
        if reset and str(reset).isdigit():
            return max(1, min(int(reset) - int(time.time()) + 2, 900))
        return min(60, 5 * (2 ** attempt))

    def _respect_rate_limit(self, headers) -> None:
        remaining = headers.get("X-RateLimit-Remaining")
        reset = headers.get("X-RateLimit-Reset")
        if not (remaining and str(remaining).isdigit()):
            return
        if int(remaining) > self.rate_floor:
            return
        wait = 60
        if reset and str(reset).isdigit():
            wait = max(1, min(int(reset) - int(time.time()) + 2, 900))
        self._log("quota nearly exhausted (%s left), sleeping %ds" % (remaining, wait))
        time.sleep(wait)

    def list_merged_pulls(self, repository: str, page: int) -> list:
        query = urllib.parse.urlencode({
            "state": "closed", "sort": "updated", "direction": "desc",
            "per_page": PAGE_SIZE, "page": page,
        })
        url = "%s/repos/%s/pulls?%s" % (API, repository, query)
        payload = json.loads(self._get(url, "application/vnd.github+json"))
        # state=closed 包含未合并的关闭 PR，必须过滤：它们的 diff 从未进入
        # 仓库历史，"这段代码曾真实存在过"的前提不成立。
        return [item for item in payload if item.get("merged_at")]

    def pull_diff(self, repository: str, number: int) -> str:
        cache_path = os.path.join(
            self.cache_dir, "%s-%d.diff" % (repository.replace("/", "__"), number)
        )
        if os.path.exists(cache_path):
            self.cache_hits += 1
            with open(cache_path, "r", encoding="utf-8") as handle:
                return handle.read()
        url = "%s/repos/%s/pulls/%d" % (API, repository, number)
        diff = self._get(url, "application/vnd.github.v3.diff")
        with open(cache_path, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(diff)
        return diff

    def _log(self, message: str) -> None:
        if self.verbose:
            print("  [gh] %s" % message, flush=True)


def load_repos(path: str) -> dict:
    try:
        import yaml
    except ImportError as exc:  # pragma: no cover - environment dependent
        raise SystemExit(
            "PyYAML is required to read the repository plan: pip install PyYAML"
        ) from exc
    with open(path, "r", encoding="utf-8") as handle:
        return yaml.safe_load(handle)


def _parse_as_of(value: str) -> datetime:
    text = value.strip().replace("Z", "+00:00")
    parsed = datetime.fromisoformat(text)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def collect(
    client: GitHub, plan: dict, cutoff: str, target_total: int,
    clean_target_total: int = 0, as_of: str = "",
) -> tuple:
    """Collect positive (reverted-fix) and clean (negative) cases in one pass.

    两条路径共享同一次 list_merged_pulls 分页和同一次 pull_diff 请求——
    不为负样本单独发一轮网络请求，见模块开头的限流策略说明。

    一个 PR 只会被尝试进其中一条路径，不会两条都试：build_case 要求标题
    命中 FIX_KEYWORDS，build_clean_case 要求不命中，两者在标题判定上互斥，
    对同一个 PR 同时跑两次是浪费。这里按"哪条路径配额还没满就先尝试哪条"
    分流，配额都满了的 PR 直接跳过（不计入任何一侧的 rejections，因为
    它没有被判定过，只是没被尝试）。
    """
    as_of_dt = _parse_as_of(as_of) if as_of else datetime.now(timezone.utc)
    cases = []
    clean_cases = []
    rejections: dict = {}
    clean_rejections: dict = {}
    default_pages = int((plan.get("defaults") or {}).get("max_pages", 12))
    # 内容级去重跨仓库、跨正负样本共享，不是每仓库/每 split 一份：既要防止
    # validation 与 holdout 拿到同一修复，也要防止同一个 PR 号同时被判成
    # 正负样本（负样本用原始 diff、正样本用反转 diff，指纹不同，所以这里
    # 额外按 (repository, number) 去重，不能只靠内容指纹）。
    seen_fingerprints: dict = {}
    seen_pull_ids: set = set()

    for entry in plan["repos"]:
        repository = entry["name"]
        split = entry["split"]
        quota = int(entry.get("target_prs", 5))
        # clean_target_total 是整个负样本路径的主开关：即便 repos.yaml 给了
        # 某个仓库 clean_target_prs，只要调用方没有传非零的 clean_target_total
        # （即命令行没显式给 --clean-target），这里也强制清零。不这样做的话，
        # repos.yaml 里配了 clean_target_prs 就会让"不加 --clean-target 就
        # 不采负样本"这条默认行为失效——见 main() 里 --clean-target 的
        # help 文案，这个默认关闭是刻意的，不能被 repos.yaml 的配置绕过。
        clean_quota = (
            int(entry.get("clean_target_prs", 0)) if clean_target_total > 0 else 0
        )
        max_pages = int(entry.get("max_pages", default_pages))
        accepted = 0
        clean_accepted = 0
        print("\n== %s (%s, want %d, clean %d) ==" % (
            repository, split, quota, clean_quota), flush=True)

        for page in range(1, max_pages + 1):
            if accepted >= quota and clean_accepted >= clean_quota:
                break
            try:
                pulls = client.list_merged_pulls(repository, page)
            except BudgetExhausted as exc:
                # 预算用尽不是失败：已采到的 case 和已统计的淘汰原因都有效，
                # 照常返回让上层出报告。抛到最外层会丢掉这一轮的全部成果。
                print("\n[budget] %s — stopping early, keeping what we have"
                      % exc, flush=True)
                return cases, rejections, clean_cases, clean_rejections
            except LookupError as exc:
                print("  skipping repository: %s" % exc, flush=True)
                break
            if not pulls:
                break
            for item in pulls:
                if accepted >= quota and clean_accepted >= clean_quota:
                    break
                number = int(item["number"])
                pull_id = (repository, number)
                if pull_id in seen_pull_ids:
                    continue

                want_positive = accepted < quota
                want_clean = not want_positive and clean_accepted < clean_quota
                if not want_positive and not want_clean:
                    continue

                title = item.get("title") or ""
                body = item.get("body") or ""
                # 标题级淘汰在抓 diff **之前**做：这两条规则不需要 diff，
                # 而 diff 是唯一要花请求的东西。首轮 pilot 实测 53 次请求里
                # 42 次浪费在"抓完 diff 才发现是 dependabot bump"上。
                # 淘汰原因照常记账，漏斗统计口径不变。
                if want_positive:
                    screened = screen_title(title, body)
                    bucket, bucket_key = rejections, "screened"
                else:
                    screened = screen_title_for_clean(title, body)
                    bucket, bucket_key = clean_rejections, "screened"
                if screened is not None:
                    bucket[screened] = bucket.get(screened, 0) + 1
                    continue

                try:
                    diff = client.pull_diff(repository, number)
                except BudgetExhausted as exc:
                    print("\n[budget] %s — stopping early, keeping what we have"
                          % exc, flush=True)
                    return cases, rejections, clean_cases, clean_rejections
                except LookupError:
                    bucket["diff-unavailable"] = bucket.get("diff-unavailable", 0) + 1
                    continue
                pull = PullRequest(
                    repository=repository,
                    number=number,
                    title=title,
                    body=body,
                    merged_at=item["merged_at"],
                    diff=diff,
                    html_url=item.get("html_url") or "",
                )

                if want_positive:
                    try:
                        case = build_case(pull, split, cutoff, entry.get("domain", ""))
                        # 与既有 harness 一致是硬要求。校验失败当成淘汰，不中断
                        # 采集：单条坏数据不该毁掉一轮几百次请求的成果。
                        validate_case(case)
                    except CaseRejected as exc:
                        rejections[exc.reason] = rejections.get(exc.reason, 0) + 1
                        continue
                    except ValueError as exc:
                        rejections["validate-case-failed"] = (
                            rejections.get("validate-case-failed", 0) + 1
                        )
                        print("  ! #%d rejected by validate_case: %s" % (number, exc),
                              flush=True)
                        continue
                    # 内容指纹按**反转后的待审 diff**算，也就是 agent 真正看到的
                    # 输入。两条 case 输入相同就是重复，无论它们来自哪个 PR。
                    fingerprint = diff_fingerprint(case["diff"])
                    if fingerprint in seen_fingerprints:
                        rejections["duplicate-diff"] = (
                            rejections.get("duplicate-diff", 0) + 1
                        )
                        print("  = #%-6d duplicate of %s" % (
                            number, seen_fingerprints[fingerprint]), flush=True)
                        continue
                    seen_fingerprints[fingerprint] = case["id"]
                    seen_pull_ids.add(pull_id)
                    cases.append(case)
                    accepted += 1
                    print("  + #%-6d %-16s %s  %s" % (
                        number, case["defect_class"], case["difficulty"],
                        case["contamination_split"],
                    ), flush=True)
                else:
                    try:
                        clean_case = build_clean_case(
                            pull, split, cutoff, as_of_dt, entry.get("domain", ""),
                        )
                        validate_case(clean_case)
                    except CaseRejected as exc:
                        clean_rejections[exc.reason] = (
                            clean_rejections.get(exc.reason, 0) + 1
                        )
                        continue
                    except ValueError as exc:
                        clean_rejections["validate-case-failed"] = (
                            clean_rejections.get("validate-case-failed", 0) + 1
                        )
                        print("  ! #%d (clean) rejected by validate_case: %s"
                              % (number, exc), flush=True)
                        continue
                    fingerprint = diff_fingerprint(clean_case["diff"])
                    if fingerprint in seen_fingerprints:
                        clean_rejections["duplicate-diff"] = (
                            clean_rejections.get("duplicate-diff", 0) + 1
                        )
                        print("  = #%-6d (clean) duplicate of %s" % (
                            number, seen_fingerprints[fingerprint]), flush=True)
                        continue
                    seen_fingerprints[fingerprint] = clean_case["id"]
                    seen_pull_ids.add(pull_id)
                    clean_cases.append(clean_case)
                    clean_accepted += 1
                    print("  ~ #%-6d clean            %s" % (
                        number, clean_case["contamination_split"],
                    ), flush=True)

        if accepted < quota:
            print("  (only %d/%d accepted — funnel is tight on this repo)"
                  % (accepted, quota), flush=True)
        if clean_quota and clean_accepted < clean_quota:
            print("  (only %d/%d clean accepted — funnel is tight on this repo)"
                  % (clean_accepted, clean_quota), flush=True)
        if len(cases) >= target_total and len(clean_cases) >= clean_target_total:
            print("\nreached target of %d cases (%d clean)"
                  % (target_total, clean_target_total), flush=True)
            break

    return cases, rejections, clean_cases, clean_rejections


def print_report(cases: list, rejections: dict, label: str = "collected") -> bool:
    report = summarise(cases, rejections)
    print("\n" + "=" * 66)
    print("%s %d cases" % (label, report.total))
    # 顺序有讲究：defect class basis **紧跟** defect class。
    # 原来这两块被 contamination / label provenance 隔开了，注释写着"紧跟"
    # 但代码不是——读者看完 "logic-boundary 89%" 会直接往下用，隔了两块
    # 表格才看到"其中 61% 是兜底值"就晚了。
    fallback_share = 0.0
    if report.total:
        fallback_share = (
            report.by_class_basis.get("fallback-default", 0) / report.total
        )
    for title, bucket in (
        ("split", report.by_split),
        ("difficulty", report.by_difficulty),
        ("defect class", report.by_class),
        ("defect class basis", report.by_class_basis),
        ("contamination", report.by_contamination),
        ("label provenance", report.by_provenance),
    ):
        print("\n%s:" % title)
        # 兜底占比过线时，直接把"别拿这张表报数"贴在表头上。
        # 光靠末尾的 WARNINGS 块不够：表格是会被单独截图贴进报告的，
        # 警告留在几十行之后就跟着丢了。
        if title == "defect class" and fallback_share > MAX_FALLBACK_SHARE:
            print("  (%.0f%% of these labels are fallback defaults — see "
                  "'defect class basis' below; do NOT report per-class metrics)"
                  % (100.0 * fallback_share))
        for key in sorted(bucket):
            share = 100.0 * bucket[key] / max(1, report.total)
            print("  %-18s %3d  (%4.1f%%)" % (key, bucket[key], share))

    print("\nrejection funnel (why candidates were dropped):")
    total_rejected = sum(rejections.values())
    for reason in sorted(rejections, key=lambda key: -rejections[key]):
        print("  %-28s %4d" % (reason, rejections[reason]))
    print("  %-28s %4d" % ("TOTAL REJECTED", total_rejected))

    if report.warnings:
        print("\nWARNINGS (the sampling plan was not met — do not ignore these):")
        for text in report.warnings:
            print("  ! %s" % text)
    return not any("HARD CONSTRAINT VIOLATED" in text for text in report.warnings)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repos", default="datasets/repos.yaml")
    parser.add_argument("--output", default="datasets/real-pr-v1.jsonl")
    parser.add_argument("--clean-output", default="datasets/real-pr-clean-v1.jsonl",
                        help="output path for clean (negative) cases")
    parser.add_argument("--cache", default="datasets/.diff-cache")
    parser.add_argument("--cutoff", default="",
                        help="model knowledge cutoff; overrides repos.yaml")
    parser.add_argument("--target", type=int, default=0,
                        help="stop after this many cases; overrides repos.yaml")
    parser.add_argument(
        "--clean-target", type=int, default=0,
        help=("stop after this many clean (negative) cases; overrides "
              "repos.yaml's per-repo clean_target_prs. Defaults to 0 "
              "(collect no clean cases) so an existing run's output shape "
              "does not change unless this is asked for explicitly."),
    )
    parser.add_argument(
        "--as-of", default="",
        help=("ISO timestamp used as 'now' for the clean-split cooldown check "
              "(CLEAN_COOLDOWN_DAYS). Defaults to the actual current time. "
              "Exists so a run can be reproduced exactly."),
    )
    parser.add_argument("--report-only", action="store_true",
                        help="re-report an existing JSONL without collecting")
    parser.add_argument(
        "--pilot", nargs="?", type=int, const=PILOT_BUDGET, default=0,
        metavar="N",
        help=("Run a hard-capped pilot of at most N requests (default %d) and "
              "allow running without GITHUB_TOKEN. This exists to verify the "
              "live paging/filtering path and to measure the real rejection "
              "funnel rate before spending a full authenticated run. The "
              "output is NOT the dataset: it is written to --output with a "
              "'.pilot' suffix so it cannot be mistaken for one."
              % PILOT_BUDGET),
    )
    args = parser.parse_args()

    if args.report_only:
        with open(args.output, "r", encoding="utf-8") as handle:
            cases = [json.loads(line) for line in handle if line.strip()]
        return 0 if print_report(cases, {}) else 1

    plan = load_repos(args.repos)
    cutoff = args.cutoff or plan.get("cutoff") or "2024-07-01"
    target = args.target or int(plan.get("target_total", 100))
    # clean_target 只看 --clean-target，不回落到 repos.yaml 的
    # clean_target_total：这是负样本路径的显式开关，即使 repos.yaml 配了
    # 总量，不传这个 flag 就必须保持不采（help 文案已经写明这一点）。
    clean_target = args.clean_target

    token = os.environ.get("GITHUB_TOKEN", "")
    if not token and not args.pilot:
        # 不静默降级：未认证 60 次/小时，采 100 个 PR 要跑十几个小时且大概率
        # 中途失败。宁可现在就说清楚。--pilot 是显式的例外，见其 help。
        print(
            "GITHUB_TOKEN is not set. Unauthenticated GitHub allows 60 requests/hour, "
            "which is not enough for ~650 requests. Set a token (no scopes needed "
            "for public repositories) and re-run, or use --pilot to run a "
            "hard-capped verification pass that does not produce the dataset.",
            file=sys.stderr,
        )
        return 2

    if args.pilot:
        # pilot 的产出必须无法被误当成数据集。改文件名而不是加字段：
        # 字段会被下游忽略，文件名不会。
        args.output = args.output + ".pilot"
        args.clean_output = args.clean_output + ".pilot"
        print("PILOT MODE: at most %d requests, %s auth, writing %s (+ %s if any clean cases)"
              % (args.pilot, "with" if token else "WITHOUT", args.output, args.clean_output))

    client = GitHub(
        token, args.cache,
        max_requests=args.pilot,
        # 未认证时 floor 必须降到 0，否则第 10 次请求就睡到下个小时。
        rate_floor=RATE_FLOOR if token else 0,
    )
    started = time.time()
    cases, rejections, clean_cases, clean_rejections = collect(
        client, plan, cutoff, target, clean_target, args.as_of,
    )

    ok = print_report(cases, rejections, "collected")
    clean_ok = True
    if clean_target or clean_cases or clean_rejections:
        clean_ok = print_report(clean_cases, clean_rejections, "collected (clean)")
    print("\n%d API requests, %d served from cache, %.1f min elapsed" % (
        client.requests, client.cache_hits, (time.time() - started) / 60.0,
    ))
    print("positive_cases=%d clean_cases=%d" % (len(cases), len(clean_cases)))

    if not cases and not clean_cases:
        print("no cases collected; nothing written", file=sys.stderr)
        return 1

    if cases:
        os.makedirs(os.path.dirname(os.path.abspath(args.output)), exist_ok=True)
        with open(args.output, "w", encoding="utf-8", newline="\n") as handle:
            for case in cases:
                handle.write(json.dumps(case, ensure_ascii=False, sort_keys=True) + "\n")
        print("wrote %s" % args.output)

    if clean_cases:
        # 独立文件，不与正样本混进同一个 .jsonl：见 datasets/README.md
        # "Clean split（负样本）"一节的说明——混在一起会让"重放
        # real-pr-v1.jsonl"这句话的含义悄悄变化。
        os.makedirs(os.path.dirname(os.path.abspath(args.clean_output)), exist_ok=True)
        with open(args.clean_output, "w", encoding="utf-8", newline="\n") as handle:
            for case in clean_cases:
                handle.write(json.dumps(case, ensure_ascii=False, sort_keys=True) + "\n")
        print("wrote %s" % args.clean_output)

    return 0 if (ok and clean_ok) else 1


if __name__ == "__main__":
    raise SystemExit(main())
