"""跑一次回放门禁的拒绝证明。见 evoagent/rejection_proof.py 的模块文档。"""
import argparse
import os
import sys


ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from evoagent.rejection_proof import (  # noqa: E402
    SCENARIOS,
    generate_rejection_cases,
    run_rejection_proof,
    write_jsonl,
    write_report,
)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Prove that the replay gate rejects a candidate that should be rejected."
    )
    parser.add_argument("--dataset", default="")
    parser.add_argument(
        "--scenario", default="holdout_regression", choices=sorted(SCENARIOS),
    )
    parser.add_argument(
        "--output-dir", default=os.path.join("output", "rejection-proof"),
    )
    args = parser.parse_args()
    os.makedirs(args.output_dir, exist_ok=True)
    dataset_path = args.dataset or os.path.join(
        args.output_dir, "rejection-proof-cases.jsonl"
    )
    if not args.dataset:
        write_jsonl(generate_rejection_cases(), dataset_path)
    database_path = os.path.join(args.output_dir, "rejection-proof.db")
    if os.path.exists(database_path):
        raise SystemExit(
            "proof database already exists; choose a fresh --output-dir for an immutable run"
        )
    report = run_rejection_proof(dataset_path, database_path, args.scenario)
    paths = write_report(report, args.output_dir)
    print("scenario:", report["scenario"]["key"])
    print("decision:", report["evolution_run"]["decision"])
    print("failing gates:", ", ".join(report["evolution_run"]["failing_gates"]) or "none")
    print("proof passed:", report["verdict"]["proof_passed"])
    print("json:", paths["json"])
    print("markdown:", paths["markdown"])
    # 证明失败时以非零码退出，这样它能直接进 CI —— 一个"证明"如果失败了
    # 还静默返回 0，那它就不是证明。
    if not report["verdict"]["proof_passed"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()