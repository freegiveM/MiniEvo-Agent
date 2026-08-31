"""Run the fair four-arm evaluation against the product LLM runtime."""
import argparse
import json
import os
import sys


ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from evoagent.evaluation_harness import load_jsonl  # noqa: E402
from evoagent.evaluation_v2 import (  # noqa: E402
    FairAblationSuite,
    product_reviewer_factories,
)
from evoagent.llm import JsonChatClient  # noqa: E402


def main():
    parser = argparse.ArgumentParser(
        description=(
            "Compare rules-only, one LLM reviewer, three LLM roles without "
            "Critic, and the complete four-role agentic topology."
        )
    )
    parser.add_argument("dataset", help="Human-labelled public/historical PR JSONL")
    parser.add_argument("--base-url", default=os.getenv("EVOAGENT_LLM_BASE_URL", ""))
    parser.add_argument("--api-key", default=os.getenv("EVOAGENT_LLM_API_KEY", ""))
    parser.add_argument("--model", default=os.getenv("EVOAGENT_LLM_MODEL", ""))
    parser.add_argument("--provider", default=os.getenv("EVOAGENT_LLM_PROVIDER", "custom"))
    parser.add_argument("--timeout", type=int, default=120)
    parser.add_argument("--token-budget", type=int, default=12000)
    parser.add_argument("--time-budget", type=int, default=240)
    parser.add_argument("--bootstrap-iterations", type=int, default=2000)
    parser.add_argument("--bootstrap-seed", type=int, default=20260819)
    parser.add_argument(
        "--allow-non-production-data", action="store_true",
        help="Run for harness debugging but keep all proof/launch gates closed.",
    )
    parser.add_argument(
        "--output", default=os.path.join(
            ROOT, "output", "agentic-evaluation", "evaluation.json",
        ),
    )
    args = parser.parse_args()
    if not args.base_url or not args.api_key or not args.model:
        parser.error("--base-url, --api-key and --model are required")
    if args.token_budget < 1024:
        parser.error("--token-budget must be at least 1024 for four LLM roles")
    if args.time_budget < 4:
        parser.error("--time-budget must be at least 4 seconds")

    client = JsonChatClient(
        args.base_url, args.api_key, args.model,
        provider=args.provider, timeout=args.timeout,
    )
    suite = FairAblationSuite(
        product_reviewer_factories(client, args.time_budget),
        args.model, args.token_budget,
        require_production_ready=not args.allow_non_production_data,
        bootstrap_iterations=args.bootstrap_iterations,
        bootstrap_seed=args.bootstrap_seed,
    )
    report = suite.run(load_jsonl(args.dataset))
    output = os.path.abspath(args.output)
    os.makedirs(os.path.dirname(output), exist_ok=True)
    with open(output, "w", encoding="utf-8", newline="\n") as handle:
        json.dump(report, handle, ensure_ascii=False, indent=2, sort_keys=True)
        handle.write("\n")
    print(output)


if __name__ == "__main__":
    main()
