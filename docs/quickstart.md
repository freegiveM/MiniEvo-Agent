# 快速开始

项目使用 Python 3.11。**服务本体不需要任何第三方依赖**——HTTP 走标准库
`http.server`，存储走 `sqlite3`，LLM 调用走 `urllib`。`requirements.txt`
里只剩一个 PyYAML（数据集采集脚本用），可选功能拆成了 extras，见
`pyproject.toml`。

```bash
git clone https://github.com/freegiveM/MiniEvo-Agent.git && cd MiniEvo-Agent
python -m pip install -r requirements.txt
python -m pytest -q          # 不需要 API key、不需要联网
```

跑通测试是验证 clone 完整的最快方式。基线是 876 passed / 58 subtests。

### 起服务

**Linux / macOS / Git Bash：**

```bash
export EVOAGENT_AUTH_REQUIRED=true
export EVOAGENT_AUTH_SECRET="$(python -c 'import base64,os;print(base64.b64encode(os.urandom(32)).decode())')"
export EVOAGENT_BOOTSTRAP_ADMIN_USERNAME=admin
export EVOAGENT_BOOTSTRAP_ADMIN_PASSWORD='<替换为至少 10 个字符的密码>'

python -m evoagent
```

**PowerShell：**

```powershell
$bytes = New-Object byte[] 32
[Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
$env:EVOAGENT_AUTH_REQUIRED = 'true'
$env:EVOAGENT_AUTH_SECRET = [Convert]::ToBase64String($bytes)
$env:EVOAGENT_BOOTSTRAP_ADMIN_USERNAME = 'admin'
$env:EVOAGENT_BOOTSTRAP_ADMIN_PASSWORD = '<替换为至少 10 个字符的密码>'

python -m evoagent
```

不配 LLM key 也能起来：此时 `rules-only` 模式可用（正则规则 + 技能），
`hybrid` / `agentic` 需要 `EVOAGENT_DEEPSEEK_API_KEY`（见 `.env.example`）。

不要直接使用示例占位符作为密码或密钥。环境变量只对当前 shell 及其子进程生效；修改配置后需要停止并重新启动 EvoAgent。

Bootstrap 管理员只在用户名尚不存在时创建；已有同名用户的密码不会在重启时被覆盖。

服务默认监听 `127.0.0.1:8080`。启动后打开 `http://127.0.0.1:8080/`，前端会在业务 API 返回未授权状态后显示登录层。登录状态保存在当前浏览器的 `localStorage` 中；需要重新登录时可以点击退出，或清除站点数据。

### 提一次审查

API 调用需要先登录并携带 Bearer Token。登录用的是上面启动时设定的
`EVOAGENT_BOOTSTRAP_ADMIN_USERNAME` / `EVOAGENT_BOOTSTRAP_ADMIN_PASSWORD`
——这是本服务自己的账号，与 GitHub 账号无关。`repository` 是必填的。

**curl（Linux / macOS / Git Bash）：**

```bash
TOKEN=$(curl -s -X POST http://127.0.0.1:8080/v1/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"<BOOTSTRAP_ADMIN_PASSWORD 的值>"}' \
  | python -c "import sys,json;print(json.load(sys.stdin)['access_token'])")

curl -s -X POST http://127.0.0.1:8080/v1/reviews \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"repository":"demo/api","pull_request":12,"mode":"rules-only",
       "diff":"--- a/app.py\n+++ b/app.py\n@@ -1 +1,2 @@\n+password = \"secret\"\n+eval(user_input)\n"}'
```

**PowerShell：**

```powershell
$session = Invoke-RestMethod -Method Post -Uri http://127.0.0.1:8080/v1/auth/login `
  -ContentType 'application/json' `
  -Body (@{username='admin'; password='<BOOTSTRAP_ADMIN_PASSWORD 的值>'} | ConvertTo-Json)
$headers = @{Authorization="Bearer $($session.access_token)"}
Invoke-RestMethod -Method Post -Uri http://127.0.0.1:8080/v1/reviews `
  -Headers $headers `
  -ContentType 'application/json' `
  -Body (@{
    repository = 'demo/api'
    pull_request = 12
    mode = 'rules-only'
    diff = "diff --git a/app.py b/app.py`n--- a/app.py`n+++ b/app.py`n@@ -1 +1,2 @@`n+password = 'secret'`n+eval(user_input)"
  } | ConvertTo-Json)
```

查询任务：

```bash
curl -s -H "Authorization: Bearer $TOKEN" http://127.0.0.1:8080/v1/tasks/<task-id>
curl -s -H "Authorization: Bearer $TOKEN" http://127.0.0.1:8080/v1/tasks/<task-id>/report
```

运行测试：

```bash
python -m pytest -q
```

