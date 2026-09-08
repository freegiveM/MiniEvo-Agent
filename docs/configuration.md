# 模型与运行配置

每个请求可提交 `mode`：`rules-only`（纯扫描）、`hybrid`（扫描 + 单 LLM）或 `agentic`（Planner、Security、Correctness/Reliability、Critic 四个独立 LLM 角色）。后两者在没有模型配置时会明确降级到 `rules-only`。

每份 JSON/Markdown 报告包含实际模型调用数、工具调用数、输入/输出 Token、成本、延迟、失败调用和完整 Agent 轨迹。成本来自供应商响应的 `usage.cost` 或 `EVOAGENT_LLM_*_COST_PER_MILLION`；价格未配置时显示 0，不会猜测。若服务主机已有仓库 checkout，可在请求中传入绝对路径 `repository_root`，启用仓库全文、符号/调用关系、测试、配置/权限、AST、Git 历史和已安装静态分析器。

DeepSeek 官方 API（按 Token 计费）：

```powershell
$env:EVOAGENT_LLM_PROVIDER = 'deepseek'
$env:EVOAGENT_DEEPSEEK_API_KEY = '<deepseek-api-key>'
python -m evoagent
```

通过 OpenRouter 使用有速率限制、可用性可能变化的 DeepSeek 免费模型：

```powershell
$env:EVOAGENT_LLM_PROVIDER = 'openrouter-deepseek-free'
$env:EVOAGENT_OPENROUTER_API_KEY = '<openrouter-api-key>'
python -m evoagent
```

如果指定的免费 DeepSeek 版本下线，可将 `EVOAGENT_LLM_MODEL` 改为 OpenRouter 当前提供的其他 `:free` 模型，或把 Provider 改为 `openrouter-free` 让免费路由自动选择可用模型。

任意其他 OpenAI Chat Completions 兼容端点使用 `custom`：

```powershell
$env:EVOAGENT_LLM_PROVIDER = 'custom'
$env:EVOAGENT_LLM_BASE_URL = 'https://example.com/v1'
$env:EVOAGENT_LLM_API_KEY = '<token>'
$env:EVOAGENT_LLM_MODEL = '<model-name>'
```

密钥只通过环境变量读取，不要提交到仓库。

项目启动时会自动读取项目根目录的 `.env`，也兼容 `evoagent/.env`；系统环境变量优先于 `.env` 文件。推荐将以下内容写入根目录 `.env`（该文件已被 `.gitignore` 忽略）：

```env
EVOAGENT_LLM_PROVIDER=deepseek
EVOAGENT_DEEPSEEK_API_KEY=你的真实APIKey
```

