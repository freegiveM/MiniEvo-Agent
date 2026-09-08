import os
import tempfile
import time
import unittest

from evoagent.auth import AuthManager
from evoagent.harness import ReviewHarness
from evoagent.reviewer import LocalRuleReviewer
from evoagent.rollout import ReleaseManager
from evoagent.service import ReviewService
from evoagent.store import TaskStore
from evoagent.task_queue import TaskQueue
from evoagent.verifier import RepairVerifier


DIFF = "--- a/a.py\n+++ b/a.py\n@@ -1 +1 @@\n-old\n+eval(data)\n"


class ProductionFeatureTests(unittest.TestCase):
    def setUp(self):
        handle, self.path = tempfile.mkstemp(suffix=".db")
        os.close(handle)
        self.store = TaskStore(self.path)

    def tearDown(self):
        os.unlink(self.path)

    def test_login_rbac_and_tenant_task_isolation(self):
        auth = AuthManager(
            self.store, "a" * 32, bootstrap_username="alice",
            bootstrap_password="correct-horse", default_tenant_id="tenant-a",
        )
        token = auth.login("alice", "correct-horse")["access_token"]
        principal = auth.authenticate("Bearer " + token)
        self.assertTrue(principal.can("manage"))
        self.store.create("a", "org/a", 1, {}, "tenant-a")
        self.store.create("b", "org/b", 2, {}, "tenant-b")
        self.assertIsNotNone(self.store.get("a", principal.tenant_id))
        self.assertIsNone(self.store.get("b", principal.tenant_id))
        self.assertEqual(["a"], [item["id"] for item in self.store.list_tasks(10, "tenant-a")])

    def test_webhook_delivery_is_idempotent_and_payload_bound(self):
        self.assertTrue(self.store.claim_webhook("delivery-1", "t", "pull_request", "aaa"))
        self.assertFalse(self.store.claim_webhook("delivery-1", "t", "pull_request", "aaa"))
        with self.assertRaisesRegex(ValueError, "different payload"):
            self.store.claim_webhook("delivery-1", "t", "pull_request", "bbb")

    def test_failure_cases_are_filtered_by_tenant(self):
        self.store.create("a", "org/a", 1, {}, "tenant-a")
        self.store.create("b", "org/b", 2, {}, "tenant-b")
        self.store.record_failure_case("a", "false_positive", {"note": "a"})
        self.store.record_failure_case("b", "missed_issue", {"note": "b"})

        cases = self.store.list_failure_cases(tenant_id="tenant-a")

        self.assertEqual(["a"], [item["task_id"] for item in cases])

    def test_failed_graph_resumes_after_last_completed_checkpoint(self):
        class BrokenReviewer:
            name = "broken"

            def review(self, _diff, _parsed):
                raise RuntimeError("temporary provider failure")

        self.store.create("task", "org/repo", 1, {})
        with self.assertRaises(RuntimeError):
            ReviewHarness(
                self.store, BrokenReviewer(), node_retries=0
            ).run("task", "org/repo", 1, DIFF)
        checkpoints = self.store.load_checkpoints("task")
        self.assertEqual("completed", checkpoints["planning"]["status"])
        self.assertEqual("failed", checkpoints["executing"]["status"])

        report = ReviewHarness(
            self.store, LocalRuleReviewer(), node_retries=0
        ).resume("task", "org/repo", 1, DIFF)
        self.assertEqual("high", report.risk)
        planning_events = [
            item for item in self.store.get("task")["trace"] if item["state"] == "PLANNING"
        ]
        self.assertEqual(1, len(planning_events))

    def test_queue_moves_terminal_failure_to_dlq(self):
        def broken(_payload):
            raise RuntimeError("boom")

        queue = TaskQueue(broken, workers=1, max_attempts=1)
        queue.submit({"task_id": "dead"})
        for _ in range(100):
            if queue.dead_letters():
                break
            time.sleep(.01)
        letters = queue.dead_letters()
        queue.close()
        self.assertEqual("dead", letters[0]["message_id"])
        self.assertIn("boom", letters[0]["error"])

    def test_dead_letter_marks_pending_task_failed(self):
        self.store.create("dead", "org/repo", 1, {}, "tenant")
        service = ReviewService.__new__(ReviewService)
        service.store = self.store

        service._on_dead_letter({"task_id": "dead", "tenant_id": "tenant"}, "boom")

        task = self.store.get("dead", "tenant")
        self.assertEqual("FAILED", task["state"])
        self.assertEqual("boom", task["error"])

    def test_canary_assignment_and_error_budget_rollback(self):
        release = ReleaseManager(self.store)
        release.configure("tenant", "skill", {
            "stable_version": 1, "candidate_version": 2,
            "canary_percent": 100, "shadow_percent": 100,
            "min_samples": 2, "max_error_rate": .25,
        })
        self.assertEqual("canary", release.assignment("tenant", "skill", "task")["lane"])
        release.observe("tenant", "skill", True)
        result = release.observe("tenant", "skill", False)
        self.assertEqual("rolled_back", result["status"])
        self.assertTrue(self.store.list_alerts("tenant"))

    def test_shadow_promotion_syncs_active_skill_version(self):
        release = ReleaseManager(self.store)
        self.store.save_skill_version("skill", "prompt v1", 0.5, True)
        candidate = self.store.save_skill_version("skill", "prompt v2", 0.6, False)
        release.configure("tenant", "skill", {
            "stable_version": 1, "candidate_version": candidate["version"],
            "canary_percent": 0, "shadow_percent": 100,
            "min_samples": 2, "max_disagreement_rate": .5,
            "max_error_rate": .5, "auto_promote": True,
        })

        active_before = self.store.get_active_skill_version("skill")
        self.assertEqual(1, active_before["version"])

        primary = {"finding_keys": ["a"]}
        release.observe_shadow("tenant", "skill", "task-1", "canary", primary, primary)
        result = release.observe_shadow("tenant", "skill", "task-2", "canary", primary, primary)

        self.assertEqual("promoted", result["status"])
        active_after = self.store.get_active_skill_version("skill")
        self.assertEqual(candidate["version"], active_after["version"])

    def test_shadow_promotion_leaves_active_alone_when_the_version_is_unknown(self):
        """候选版本不在 skill_versions 里时，同步静默跳过——这是个隐患，钉住它。

        `record_shadow_observation` 的同步分支有一道存在性检查：
        `SELECT 1 FROM skill_versions WHERE skill_name=? AND version=?`。
        `deployments.candidate_version` 是 `configure` 直接透传的任意整数，
        没有外键约束，调用方给一个 `skill_versions` 里不存在的号完全合法。

        此时的行为是：deployment 照常 promoted，但 `skill_versions.active`
        **原地不动**，而且没有任何告警——`evolution.py` 下一轮读 baseline
        仍然拿到旧版本，正是轨道 B 要修的那种"两张表悄悄分叉"。

        这条测试不主张当前行为是对的（不同步好过错同步，但静默是坏的）。
        它的作用是：谁要改成抛错或告警，得先来改这条测试，而不是让这个
        分支继续没人知道地存在。
        """
        release = ReleaseManager(self.store)
        self.store.save_skill_version("skill", "prompt v1", 0.5, True)
        release.configure("tenant", "skill", {
            "stable_version": 1, "candidate_version": 999,
            "canary_percent": 0, "shadow_percent": 100,
            "min_samples": 2, "max_disagreement_rate": .5,
            "max_error_rate": .5, "auto_promote": True,
        })

        primary = {"finding_keys": ["a"]}
        release.observe_shadow("tenant", "skill", "task-1", "canary", primary, primary)
        result = release.observe_shadow("tenant", "skill", "task-2", "canary", primary, primary)

        self.assertEqual("promoted", result["status"])
        # 不会把 active 清空成"一个都没有"——那比不同步更糟，
        # get_active_skill_version 返回 None 会让下一轮 baseline 直接消失。
        self.assertEqual(1, self.store.get_active_skill_version("skill")["version"])

    def test_repair_verifier_blocks_invalid_python(self):
        result = RepairVerifier().verify_contents({"app.py": "def broken(:\n"})
        self.assertFalse(result["passed"])
        self.assertEqual("compile:app.py", result["checks"][0]["name"])


if __name__ == "__main__":
    unittest.main()
