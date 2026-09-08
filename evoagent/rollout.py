"""Deterministic canary and shadow assignment with automatic rollback."""
import hashlib
from typing import Dict, Optional


class ReleaseManager:
    def __init__(self, store):
        self.store = store

    def configure(self, tenant_id: str, skill_name: str, config: Dict[str, object]) -> dict:
        canary = int(config.get("canary_percent", 0))
        shadow = int(config.get("shadow_percent", 0))
        if not 0 <= canary <= 100 or not 0 <= shadow <= 100:
            raise ValueError("canary_percent and shadow_percent must be between 0 and 100")
        if config.get("candidate_version") is None:
            raise ValueError("candidate_version is required")
        self.store.save_deployment(tenant_id, skill_name, config)
        return self.store.get_deployment(tenant_id, skill_name)

    def stage_shadow(
        self, tenant_id: str, skill_name: str, candidate_version: int,
        stable_version: Optional[int] = None, shadow_percent: int = 100,
        auto_promote: bool = False,
    ) -> Dict[str, object]:
        """把一个通过了回放门禁的候选放上影子流量。

        ## 为什么需要这个方法：`shadow_ready` 之前是死路

        `auto_propose` 的 LLM 路径固定走 `activation_policy="shadow"`，判决
        永远是 `shadow_ready`。但在这个方法之前，**没有任何代码消费这个
        判决**——候选要真上影子流量，得有人另外去查版本号、手动 POST 一次
        `/v1/deployments/llm-review`。于是"回放门禁通过"和"开始收集影子
        证据"之间是断开的，闭环在这里断第二次。

        ## 守卫：不覆盖正在累积证据的部署

        `save_deployment` 会把 `samples/errors/shadow_samples/disagreements`
        全部重置为 0。如果自动接线直接覆盖一个正在跑的部署，就会擦掉正在
        累积的错误预算——一个刚要触发回滚的金丝雀会重新变得"干净"，而
        `record_deployment_result` 的回滚门禁正是靠 `samples` 判断的。那是
        用一次自动化把一个安全机制静默解除。

        所以这里的默认是**拒绝**而不是覆盖：已有一个 running 部署且候选
        版本不同时返回 `staged: False` 并说明原因，交给人决定。同一个候选
        版本重复调用是幂等的（不重置证据，直接返回现状）。

        `auto_promote` 默认 False。影子观测自动晋升上线是一个应该由人显式
        打开的开关——把它默认开着，等于让"分歧率低"这一个指标独自决定
        上线，而分歧率低也可能只是候选和基线一起漏了同一批问题。
        """
        existing = self.store.get_deployment(tenant_id, skill_name)
        if existing and existing["status"] == "running":
            if int(existing["candidate_version"] or 0) == int(candidate_version):
                # 幂等：同一个候选已经在影子流量上，不重置它已累积的证据。
                return {
                    "staged": False, "reason": "candidate is already on shadow traffic",
                    "deployment": existing, "clobbered": False,
                }
            return {
                "staged": False,
                "reason": (
                    "a different candidate (version %s) is already running with %s "
                    "canary and %s shadow samples; staging would reset that evidence"
                    % (existing["candidate_version"], existing["samples"],
                       existing["shadow_samples"])
                ),
                "deployment": existing, "clobbered": False,
            }
        if stable_version is None:
            active = self.store.get_active_skill_version(skill_name)
            stable_version = active["version"] if active else None
        self.store.save_deployment(tenant_id, skill_name, {
            # canary 恒为 0：影子是"跑但不采用其输出"，金丝雀是"真的把
            # 结果给用户"。回放门禁通过只够上影子，让候选直接吃真实流量
            # 需要影子阶段的证据先攒够。
            "canary_percent": 0,
            "shadow_percent": max(0, min(100, int(shadow_percent))),
            "candidate_version": int(candidate_version),
            "stable_version": stable_version,
            "auto_promote": bool(auto_promote),
            "status": "running",
        })
        deployment = self.store.get_deployment(tenant_id, skill_name)
        return {"staged": True, "reason": "", "deployment": deployment,
                "clobbered": False}

    def evaluate_promotion(
        self, tenant_id: str, skill_name: str,
        min_wins: Optional[int] = None,
    ) -> Dict[str, object]:
        """按影子证据判决晋升——闭环最后一段。

        ## 这个方法之前，候选上得去下不来

        `stage_shadow` 把候选放上影子流量，`observe_shadow` 逐条记录观测，
        然后就没有了。全代码库唯一的晋升路径是 `record_shadow_observation`
        里的 `auto_promote` 分支，而 `stage_shadow` 刻意把 `auto_promote` 设成
        False。于是影子证据只进不出：要么永远停在影子上，要么靠人手动打开
        那个开关——而打开它就等于让分歧率独自决定上线，正是 `stage_shadow`
        文档里写明拒绝的做法。

        ## 为什么低分歧率不能当通过条件

        候选和基线**一起漏掉同一批问题**时，分歧率是 0.0，完美通过任何
        "分歧率 ≤ 阈值"的门禁。一个什么都没改进的候选会因此被自动上线。
        所以通过条件另立一条：候选至少要赢过 `min_wins` 次
        （`candidate_only > 0` 的观测数）。

        ## 为什么否决看的也不是对称分歧率

        对称分歧率同样不能当否决条件——一个每次都多报一条问题的候选，对称
        分歧率是 1.0，会被"分歧率 ≤ 阈值"当成退化拦下。风险在**漏**不在多：
        门禁看 `loss_rate`（候选漏掉基线发现的观测占比），对称分歧率只作展示。
        这正是 `observe_shadow` 要分方向记的原因。

        ## 三态，不是布尔

        `insufficient_evidence` 与 `reject` 必须分开。合成同一个 False 会让
        一个还没攒够样本的候选看起来像是被否决过——这是把"没测"读成
        "测了不合格"，与 `summarise_shadow_evidence` 里分母为 0 返回 None
        是同一条纪律。

        ## 这个判决不声称什么

        候选独有的发现**没有人工标注**，影子期无法区分"候选更准"和"候选
        误报更多"。所以 `candidate_wins` 只是一个"候选在做事"的弱信号，
        理由字段里如实写着这一点，不把它表述成"候选更准确"。
        """
        deployment = self.store.get_deployment(tenant_id, skill_name)
        if not deployment:
            return self._verdict(
                "insufficient_evidence", False,
                "no deployment exists for %s/%s" % (tenant_id, skill_name),
                None, None)
        if deployment["status"] != "running":
            return self._verdict(
                "insufficient_evidence", False,
                "deployment status is %s, not running" % deployment["status"],
                deployment, None)
        candidate_version = deployment["candidate_version"]
        if candidate_version is None:
            return self._verdict(
                "insufficient_evidence", False,
                "deployment has no candidate_version to promote",
                deployment, None)

        evidence = self.store.summarise_shadow_evidence(
            tenant_id, skill_name, int(candidate_version))
        min_samples = int(deployment["min_samples"])
        if evidence["samples"] < min_samples:
            return self._verdict(
                "insufficient_evidence", False,
                "only %s shadow observations for candidate version %s; %s are "
                "required before a promotion decision can be made"
                % (evidence["samples"], candidate_version, min_samples),
                deployment, evidence)

        # 否决条件。任何一条成立就不晋升——它们各自独立，不互相补偿。
        if evidence["failures"]:
            return self._verdict(
                "reject", False,
                "the candidate failed on %s of %s shadow observations"
                % (evidence["failures"], evidence["samples"]),
                deployment, evidence)
        rate = evidence["loss_rate"]
        maximum = float(deployment["max_disagreement_rate"])
        if rate is not None and rate > maximum:
            return self._verdict(
                "reject", False,
                "the candidate lost baseline findings on %.0f%% of observations, "
                "above the configured maximum disagreement rate %.2f"
                % (100.0 * rate, maximum),
                deployment, evidence)
        # 金丝雀错误预算与影子分歧率是两道独立的门：候选可以在影子上安静
        # 无事，同时在真实流量上超预算。
        canary_samples = int(deployment["samples"])
        if canary_samples and (
            deployment["errors"] / canary_samples > float(deployment["max_error_rate"])
        ):
            return self._verdict(
                "reject", False,
                "the canary error budget is already breached (%s errors in %s "
                "requests, budget %.2f)"
                % (deployment["errors"], canary_samples, deployment["max_error_rate"]),
                deployment, evidence)

        # 通过条件。这一条独立于上面所有否决条件——安静不等于更好。
        required_wins = 1 if min_wins is None else int(min_wins)
        if evidence["candidate_wins"] < required_wins:
            return self._verdict(
                "insufficient_evidence", False,
                "the candidate produced findings the baseline missed on %s of %s "
                "observations (%s required): a low disagreement rate on its own "
                "cannot distinguish a better candidate from one that missed the "
                "same issues as the baseline"
                % (evidence["candidate_wins"], evidence["samples"], required_wins),
                deployment, evidence)

        promoted = self.store.promote_deployment(
            tenant_id, skill_name, int(candidate_version))
        if promoted is None:
            # 判决与写回之间候选被换掉了。不重试、不猜——上一轮的证据已经
            # 不属于现在的候选。
            return self._verdict(
                "insufficient_evidence", False,
                "the deployment changed between the decision and the write-back; "
                "re-evaluate against the current candidate",
                self.store.get_deployment(tenant_id, skill_name), evidence)
        self.store.create_alert(
            tenant_id, "rollout-promoted:%s" % skill_name, "info",
            "Candidate version %s of %s was promoted after %s shadow observations."
            % (candidate_version, skill_name, evidence["samples"]),
        )
        return self._verdict(
            "promote", True,
            "the candidate cleared %s shadow observations with no failures, lost "
            "baseline findings on %.0f%% of them (budget %.2f), and produced "
            "findings the baseline missed on %s; those extra findings are not "
            "confirmed true positives — shadow traffic carries no human labels"
            % (evidence["samples"], 100.0 * (rate if rate is not None else 0.0),
               maximum, evidence["candidate_wins"]),
            promoted, evidence)

    @staticmethod
    def _verdict(decision, promoted, reason, deployment, evidence) -> Dict[str, object]:
        return {
            "decision": decision, "promoted": promoted, "reason": reason,
            "deployment": deployment, "evidence": evidence,
        }

    def assignment(self, tenant_id: str, skill_name: str, key: str) -> Dict[str, object]:
        deployment = self.store.get_deployment(tenant_id, skill_name)
        if not deployment or deployment["status"] != "running":
            return {"lane": "stable", "shadow": False, "deployment": None}
        bucket = int(hashlib.sha256(
            ("%s:%s:%s" % (tenant_id, skill_name, key)).encode("utf-8")
        ).hexdigest()[:8], 16) % 100
        return {
            "lane": "canary" if bucket < deployment["canary_percent"] else "stable",
            "shadow": bucket < deployment["shadow_percent"],
            "deployment": deployment,
        }

    def observe(
        self, tenant_id: str, skill_name: str, failed: bool,
        lane: str = "canary",
    ) -> Optional[dict]:
        if lane != "canary":
            return self.store.get_deployment(tenant_id, skill_name)
        result = self.store.record_deployment_result(tenant_id, skill_name, failed)
        if result and result["status"] == "rolled_back":
            self.store.create_alert(
                tenant_id, "rollout:%s" % skill_name, "critical",
                "Canary %s was automatically rolled back after exceeding its error budget." % skill_name,
            )
        return result

    def observe_shadow(
        self, tenant_id: str, skill_name: str, task_id: str, lane: str,
        primary: Dict[str, object], candidate: Optional[Dict[str, object]],
        candidate_failed: bool = False,
    ) -> Optional[dict]:
        primary_keys = set(primary.get("finding_keys", []))
        candidate_keys = set((candidate or {}).get("finding_keys", []))
        union = primary_keys | candidate_keys
        disagreement = len(primary_keys ^ candidate_keys) / len(union) if union else 0.0
        # 分歧的方向要分开记。对称分歧率分不出"候选多报了一条"和"候选漏掉了
        # 基线报过的一条"，而这两者风险相反：前者可能是候选更强（也可能是
        # 误报），后者是能力退化。晋升判决必须能区分它们。
        result = self.store.record_shadow_observation(
            tenant_id, skill_name, task_id, lane, primary, candidate,
            disagreement, candidate_failed,
            candidate_only=len(candidate_keys - primary_keys),
            primary_only=len(primary_keys - candidate_keys),
        )
        if result and result["status"] == "promoted":
            self.store.create_alert(
                tenant_id, "rollout-promoted:%s" % skill_name, "info",
                "Candidate %s was automatically promoted after shadow verification." % skill_name,
            )
        return result
