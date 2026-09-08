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

```bash
python -m evoagent
```

没有别的了。服务监听 `127.0.0.1:8080`，存储是当前目录下的 SQLite 文件。

**不配 LLM key 也能起来**：此时 `rules-only` 模式可用（正则规则 + 技能），
`hybrid` / `agentic` 需要 `EVOAGENT_DEEPSEEK_API_KEY`（见 `.env.example`）。

**默认不需要登录。**`EVOAGENT_AUTH_REQUIRED` 默认是 `false`，此时每个请求
都被当作本机管理员处理，不必带 token。什么时候要打开它、以及那时怎么建
账号，见下面「把它暴露出去之前」。

打开 `http://127.0.0.1:8080/` 就是管理台。

### 提一次审查

`repository` 是必填的——漏掉会报 `repository is required`，那句话读起来
像认证问题，其实不是。

**curl（Linux / macOS / Git Bash）：**

```bash
curl -s -X POST http://127.0.0.1:8080/v1/reviews \
  -H 'Content-Type: application/json' \
  -d '{"repository":"demo/api","pull_request":12,"mode":"rules-only",
       "diff":"--- a/app.py\n+++ b/app.py\n@@ -1 +1,2 @@\n+password = \"secret\"\n+eval(user_input)\n"}'
```

**PowerShell：**

```powershell
Invoke-RestMethod -Method Post -Uri http://127.0.0.1:8080/v1/reviews `
  -ContentType 'application/json' `
  -Body (@{
    repository = 'demo/api'
    pull_request = 12
    mode = 'rules-only'
    diff = "--- a/app.py`n+++ b/app.py`n@@ -1 +1,2 @@`n+password = 'secret'`n+eval(user_input)"
  } | ConvertTo-Json)
```

这份 diff 是故意写坏的：硬编码密钥加 `eval(user_input)`。`rules-only`
不调用模型，所以这一步在没有任何 API key 的机器上也能看到真实结果。

查询任务：

```bash
curl -s http://127.0.0.1:8080/v1/tasks/<task-id>
curl -s http://127.0.0.1:8080/v1/tasks/<task-id>/report
```

前者是 JSON，后者是 markdown 报告。

### 把它暴露出去之前

上面那条路径假设服务只监听本机。**一旦它能被别人访问到**——接真实仓库时
用 ngrok 转发、或者部署到服务器——就必须打开认证，因为管理台里有
`skill.evolution.activate`、`deployment.promote` 这类端点：激活一个新版本
提示词会改变之后所有审查的行为。认证关闭时这些端点是无条件放行的。

```bash
export EVOAGENT_AUTH_REQUIRED=true
export EVOAGENT_AUTH_SECRET="$(python -c 'import base64,os;print(base64.b64encode(os.urandom(32)).decode())')"
export EVOAGENT_BOOTSTRAP_ADMIN_USERNAME=admin
export EVOAGENT_BOOTSTRAP_ADMIN_PASSWORD='<至少 10 个字符>'

python -m evoagent
```

**PowerShell：**

```powershell
$bytes = New-Object byte[] 32
[Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
$env:EVOAGENT_AUTH_REQUIRED = 'true'
$env:EVOAGENT_AUTH_SECRET = [Convert]::ToBase64String($bytes)
$env:EVOAGENT_BOOTSTRAP_ADMIN_USERNAME = 'admin'
$env:EVOAGENT_BOOTSTRAP_ADMIN_PASSWORD = '<至少 10 个字符>'

python -m evoagent
```

这里的用户名密码是**本服务自己的账号**，与 GitHub 账号无关；`AUTH_SECRET`
是签 JWT 用的服务端密钥，不用记也不用输。别把示例占位符当成真密码用。
Bootstrap 管理员只在用户名尚不存在时创建——已有同名用户的密码不会在重启时
被覆盖，所以改了环境变量再重启，登录用的仍是第一次那个密码。

此后每个 API 调用都要带 Bearer Token：

```bash
TOKEN=$(curl -s -X POST http://127.0.0.1:8080/v1/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"<上面设的密码>"}' \
  | python -c "import sys,json;print(json.load(sys.stdin)['access_token'])")

curl -s -H "Authorization: Bearer $TOKEN" http://127.0.0.1:8080/v1/tasks
```

管理台会在 API 返回未授权后弹出登录层，用同一对用户名密码；登录态存在
浏览器 `localStorage` 里。

**Webhook 不走这套。**`/webhooks/github` 用 HMAC-SHA256 签名验证——GitHub
不可能持有你的账号密码。两套认证是刻意分开的，细节见
[GitHub Webhook](github-webhook.md)。

### 运行测试

```bash
python -m pytest -q
```

