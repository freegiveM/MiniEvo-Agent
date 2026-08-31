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


ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from evoagent.dataset_builder import (  # noqa: E402
    CaseRejected,
    PullRequest,
    build_case,
    summarise,
)
from evoagent.evaluation_harness import validate_case  # noqa: E402

API = "https://api.github.com"
USER_AGENT = "evoagent-reverted-fix-collector"
RATE_FLOOR = 50          # 剩余配额低于此值就等重置，留余量给并发的其他调用
PAGE_SIZE = 100


class GitHub:
    def __init__(self, token: str, cache_dir: str, verbose: bool = True) -> None:
        self.token = token
        self.cache_dir = cache_dir
        self.verbose = verbose
        self.requests = 0
        self.cache_hits = 0
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
                if exc.code in (404, 451):
                    # 仓库改名/PR 被删/DMCA 下架：跳过而不是中断整轮采集。
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
        if int(remaining) > RATE_FLOOR:
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


def collect(client: GitHub, plan: dict, cutoff: str, target_total: int) -> tuple:
    cases = []
    rejections: dict = {}
    default_pages = int((plan.get("defaults") or {}).get("max_pages", 12))

    for entry in plan["repos"]:
        repository = entry["name"]
        split = entry["split"]
        quota = int(entry.get("target_prs", 5))
        max_pages = int(entry.get("max_pages", default_pages))
        accepted = 0
        print("\n== %s (%s, want %d) ==" % (repository, split, quota), flush=True)

        for page in range(1, max_pages + 1):
            if accepted >= quota:
                break
            try:
                pulls = client.list_merged_pulls(repository, page)
            except LookupError as exc:
                print("  skipping repository: %s" % exc, flush=True)
                break
            if not pulls:
                break
            for item in pulls:
                if accepted >= quota:
                    break
                number = int(item["number"])
                try:
                    diff = client.pull_diff(repository, number)
                except LookupError:
                    rejections["diff-unavailable"] = rejections.get("diff-unavailable", 0) + 1
                    continue
                pull = PullRequest(
                    repository=repository,
                    number=number,
                    title=item.get("title") or "",
                    body=item.get("body") or "",
                    merged_at=item["merged_at"],
                    diff=diff,
                    html_url=item.get("html_url") or "",
                )
                try:
                    case = build_case(pull, split, cutoff, entry.get("domain", ""))
                    # 与既有 harness 一致是硬要求。校验失败当成淘汰，不中断采集：
                    # 单条坏数据不该毁掉一轮几百次请求的成果。
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
                cases.append(case)
                accepted += 1
                print("  + #%-6d %-16s %s  %s" % (
                    number, case["defect_class"], case["difficulty"],
                    case["contamination_split"],
                ), flush=True)

        if accepted < quota:
            print("  (only %d/%d accepted — funnel is tight on this repo)"
                  % (accepted, quota), flush=True)
        if len(cases) >= target_total:
            print("\nreached target of %d cases" % target_total, flush=True)
            break

    return cases, rejections


def print_report(cases: list, rejections: dict) -> bool:
    report = summarise(cases, rejections)
    print("\n" + "=" * 66)
    print("collected %d cases" % report.total)
    for title, bucket in (
        ("split", report.by_split),
        ("difficulty", report.by_difficulty),
        ("defect class", report.by_class),
        ("contamination", report.by_contamination),
        ("label provenance", report.by_provenance),
    ):
        print("\n%s:" % title)
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
    parser.add_argument("--cache", default="datasets/.diff-cache")
    parser.add_argument("--cutoff", default="",
                        help="model knowledge cutoff; overrides repos.yaml")
    parser.add_argument("--target", type=int, default=0,
                        help="stop after this many cases; overrides repos.yaml")
    parser.add_argument("--report-only", action="store_true",
                        help="re-report an existing JSONL without collecting")
    args = parser.parse_args()

    if args.report_only:
        with open(args.output, "r", encoding="utf-8") as handle:
            cases = [json.loads(line) for line in handle if line.strip()]
        return 0 if print_report(cases, {}) else 1

    plan = load_repos(args.repos)
    cutoff = args.cutoff or plan.get("cutoff") or "2024-07-01"
    target = args.target or int(plan.get("target_total", 100))

    token = os.environ.get("GITHUB_TOKEN", "")
    if not token:
        # 不静默降级：未认证 60 次/小时，采 100 个 PR 要跑十几个小时且大概率
        # 中途失败。宁可现在就说清楚。
        print(
            "GITHUB_TOKEN is not set. Unauthenticated GitHub allows 60 requests/hour, "
            "which is not enough for ~650 requests. Set a token (no scopes needed "
            "for public repositories) and re-run.",
            file=sys.stderr,
        )
        return 2

    client = GitHub(token, args.cache)
    started = time.time()
    cases, rejections = collect(client, plan, cutoff, target)

    ok = print_report(cases, rejections)
    print("\n%d API requests, %d served from cache, %.1f min elapsed" % (
        client.requests, client.cache_hits, (time.time() - started) / 60.0,
    ))

    if not cases:
        print("no cases collected; nothing written", file=sys.stderr)
        return 1

    os.makedirs(os.path.dirname(os.path.abspath(args.output)), exist_ok=True)
    with open(args.output, "w", encoding="utf-8", newline="\n") as handle:
        for case in cases:
            handle.write(json.dumps(case, ensure_ascii=False, sort_keys=True) + "\n")
    print("wrote %s" % args.output)
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
