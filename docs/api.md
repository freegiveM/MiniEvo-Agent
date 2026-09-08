# HTTP API

| 方法 | 路径 | 说明 |
|---|---|---|
| `GET` | `/health` | 健康检查 |
| `POST` | `/v1/auth/login` | 登录并获取租户绑定的短期 Bearer Token |
| `POST` | `/v1/reviews` | 创建同步审查任务 |
| `POST` | `/v1/reviews?async=true` | 创建异步审查任务 |
| `GET` | `/v1/tasks/{id}` | 获取状态、轨迹和报告 |
| `GET` | `/v1/tasks/{id}/report` | 获取 Markdown 报告 |
| `GET` | `/v1/tasks/{id}/feedback` | 获取该已完成任务的反馈历史 |
| `POST` | `/v1/tasks/{id}/fix` | 创建自动修复分支和提交 |
| `POST` | `/v1/tasks/{id}/feedback` | 回流误报、漏报或坏修复 |
| `POST` | `/v1/tasks/{id}/cancel` | 请求取消任务 |
| `POST` | `/v1/tasks/{id}/resume` | 从最近 checkpoint 续跑任务 |
| `POST` | `/webhooks/github` | 接收 GitHub PR webhook |
| `POST` | `/v1/skills/reload` | 动态重新加载 Skill |
| `POST` | `/v1/evolution/auto` | 从失败案例生成并评测提示词版本 |
| `POST` | `/v1/evolution/propose` | 评测指定提示词候选版本 |
| `GET/POST` | `/v1/evaluation/cases` | 查询或增加版本化评测样本 |
| `GET` | `/v1/evolution/status` | 查询模型与评测门禁就绪状态 |
| `GET` | `/v1/evolution/runs` | 查询持久化的新旧版本评测记录 |
| `POST` | `/v1/skills/{name}/versions/{version}/activate` | 激活或回滚版本 |
| `POST` | `/v1/skill-evolution/auto` | 从确认反馈生成、回放并门禁 Skill 候选 |
| `POST` | `/v1/skill-evolution/propose` | 评测指定声明式 Skill artifact |
| `GET` | `/v1/skill-evolution/status?skill_name={name}` | 查询 Skill 门禁与激活版本 |
| `GET` | `/v1/skill-evolution/runs` | 查询 Skill 进化运行与指标 |
| `GET` | `/v1/skill-evolution/{name}/versions` | 查询 Skill artifact 版本链 |
| `POST` | `/v1/skill-evolution/{name}/versions/{version}/activate` | 激活或回滚 Skill artifact |
| `GET` | `/metrics` | Prometheus 文本指标 |
| `GET` | `/api/alerts` | 查询租户告警 |
| `GET` | `/api/audit` | 查询租户审计日志 |
| `GET` | `/api/queue/dead-letters` | 查询死信任务 |
| `POST` | `/v1/queue/dead-letters/replay` | 重放死信任务 |
| `GET/POST` | `/api/deployments/llm-review`、`/v1/deployments/llm-review` | 查询或配置灰度/影子发布 |
| `POST` | `/v1/deployments/llm-review/promote` | 按影子证据判决晋升（三态并附理由，不满足条件时不写库） |

`POST /v1/reviews` 的 `diff` 最大默认 1 MiB；单任务默认最多 8 步、120 秒。可通过环境变量调整，详见 `.env.example`。

完成审查后，可在任务详情的“审查反馈”区域提交 `false_positive`、`missed_issue` 或 `bad_fix`。接口要求任务已成功完成，并会将反馈按任务、租户保存；`missed_issue` 建议附带 `finding.rule_id`、`path` 和 `line`，以便后续候选学习准确的检查目标。

