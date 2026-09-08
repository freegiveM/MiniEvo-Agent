# MiniEvo-Agent

[English](docs/README.en.md) | 简体中文

一个带门禁的自进化 PR 审查 Agent。它审查真实 Pull Request，把误报与漏报回流成学习信号，自动生成候选提示词，并且**只有在验证集与 holdout 上通过非退化门禁之后**，新版本才会上线。

```bash
git clone https://github.com/freegiveM/MiniEvo-Agent.git && cd MiniEvo-Agent
python -m pip install -r requirements.txt
python -m pytest -q
```

服务本体不依赖任何第三方库——HTTP 走标准库 `http.server`，存储走 `sqlite3`。完整启动步骤见 [快速开始](docs/quickstart.md)。

## 核心概念

多数 "AI code review" 工具是一次性的：模型看一眼 diff，给出意见，结束。这个项目关心的是**下一次能不能更好**，而这件事的难点不在于让模型改提示词，在于**如何确认改完之后确实变好了**。

于是设计围绕三个约束展开：

**一、反馈必须是判断，不是日志。** 只有人确认过的反馈（误报、漏报、坏修复等白名单类别）才进入进化回路。用白名单而非黑名单是有意的——将来新增一个自动推断出的类别时，默认是被排除，而不是默认被信任。

**二、进化必须可否决。** 候选提示词要在验证集上有显著提升，**并且**在一个从未参与生成的 holdout 上不发生退化，才能激活。任何一档指标缺少分母时，门禁报"测不出来"，而不是默认放行。

**三、门禁不能假装在工作。** 这是项目里反复出现的失效模式，也是最值得说的一条：一道假装通过的门禁比一道不存在的门禁更危险。分母为 0 的指标会以"从没测过，无从退化"为由放行；分母为 1 更阴险——它会一直打印一个看起来正常的读数，而那个数字不携带任何信息。因此代码里 `None` 一律表示"没跑到"，与"测出来是 0"严格区分。

## 架构

```text
HTTP / GitHub Webhook
        │
        ▼
 ReviewService ── TaskStore (SQLite)
        │
        ▼
 ReviewHarness (状态机 / checkpoint / 预算 / 调用轨迹)
        │
        ├── ContextManager     统一 token 预算与上下文压缩
        ├── MemoryManager      working / episodic / semantic
        └── ModeRouter
              ├── rules-only   规则 Scanner → Gates
              ├── hybrid       Scanner + 单 LLM → Gates
              └── agentic      四个 LLM 角色 → Gates
                    ├── Planner       动态任务图
                    ├── Security      输入 / 权限 / 危险调用链
                    ├── Correctness   状态 / 异常 / 并发 / 资源
                    └── Critic        盲审、反例与缺失证据
```

三种运行模式是**如实披露**的：`rules-only` 不调用模型，`hybrid` 调用一次，`agentic` 走完整的四角色协作。每个角色有独立的 system prompt、上下文、工具白名单与 token/时间/步数预算，超预算记 `budget_exhausted` 后中止。

### 进化回路

```text
       ┌──────────────────────────────────────────┐
       │                                          │
   审查 PR ──► 人工确认反馈 ──► 根因指纹与频率分流   │
       ▲                              │           │
       │                              ▼           │
       │                        候选提示词生成      │
       │                              │           │
       │                              ▼           │
       │              ┌───────────────────────┐   │
       └───── 拒绝 ◄──┤ 验证集提升 + holdout   │   │
                      │ 非退化 + 显著性         ├───┘ 激活
                      └───────────────────────┘
```

被拒的候选不会被丢弃——它连同逐样本分数进入版本档案，供后续选亲使用；同一批反馈也不会被重复消费，消费账本单独记录哪条反馈在哪次运行中被尝试过、判决是什么。

设计取舍与相关论文（GEPA、DGM 等）的对应关系见 [评测与提示词进化](docs/evolution.md)。

## 文档

| | |
|---|---|
| [快速开始](docs/quickstart.md) | 安装、启动、提第一次审查 |
| [模型与运行配置](docs/configuration.md) | LLM provider、模式、预算 |
| [评测与提示词进化](docs/evolution.md) | 进化回路、门禁、数据集口径 |
| [GitHub Webhook](docs/github-webhook.md) | 接入真实仓库 |
| [HTTP API](docs/api.md) | 接口清单 |
| [生产部署](docs/deployment.md) | Docker / 队列 / 可观测性 |
| [项目状态](docs/project-status.md) | 按证据等级划分的能力清单与已知局限 |

**关于「项目状态」这份文档**：它按证据等级分组——「在评测链路上有量化结论」／「有单测但不在评测链路上」／「写了但跑不到」。一份能力清单里最容易骗人的地方不是某句话为假，而是把跑过评测的和只写完了的混在一起列，读者没法区分。想知道哪些数字是真跑出来的、置信区间多宽、哪些标签还不可信，看那份文档。

## 参与开发

见 [CONTRIBUTING.md](CONTRIBUTING.md)。测试不需要 API key、不需要联网。

## License

[MIT](LICENSE)