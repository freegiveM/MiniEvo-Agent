# MiniEvo-Agent

English | [简体中文](../README.md)

A self-evolving PR review agent with real gates. It reviews pull requests, recycles false positives and missed issues into learning signal, generates candidate prompts automatically, and activates a new version **only after it passes non-regression gates on both a validation set and a holdout**.

```bash
git clone https://github.com/freegiveM/MiniEvo-Agent.git && cd MiniEvo-Agent
python -m pip install -r requirements.txt
python -m pytest -q
```

The service itself has no third-party dependencies — HTTP runs on the standard library's `http.server`, storage on `sqlite3`. Full setup in [Quickstart](quickstart.md).

## Core idea

Most "AI code review" tools are one-shot: the model looks at a diff, gives an opinion, done. This project is about whether the *next* review is better — and the hard part there isn't getting a model to rewrite its own prompt. It's **confirming the rewrite actually helped**.

Three constraints follow from that:

**1. Feedback must be a judgment, not a log.** Only human-confirmed feedback (false positive, missed issue, bad fix, and a few other whitelisted categories) enters the evolution loop. The whitelist is deliberate: when a new machine-inferred category is added later, it is excluded by default rather than trusted by default.

**2. Evolution must be refusable.** A candidate prompt has to show a significant gain on the validation set **and** no regression on a holdout that never took part in generating it. When a metric has no denominator, the gate reports "unmeasurable" instead of quietly passing.

**3. A gate must not pretend to work.** This is the failure mode this project kept running into, and the one most worth stating: a gate that pretends to pass is more dangerous than a gate that doesn't exist. A metric with a denominator of 0 slips through on "never measured, nothing to regress from." A denominator of 1 is worse — it keeps printing a normal-looking number that carries no information. So throughout the codebase `None` means "did not run," strictly distinct from "measured zero."

## Architecture

```text
HTTP / GitHub Webhook
        │
        ▼
 ReviewService ── TaskStore (SQLite)
        │
        ▼
 ReviewHarness (state machine / checkpoint / budget / trace)
        │
        ├── ContextManager     unified token budget & compression
        ├── MemoryManager      working / episodic / semantic
        └── ModeRouter
              ├── rules-only   rule scanner → gates
              ├── hybrid       scanner + one LLM → gates
              └── agentic      four LLM roles → gates
                    ├── Planner       dynamic task graph
                    ├── Security      input / permission / dangerous calls
                    ├── Correctness   state / exceptions / concurrency
                    └── Critic        blind review, counterexamples, missing evidence
```

The three modes are disclosed honestly: `rules-only` calls no model, `hybrid` calls one, `agentic` runs the full four-role collaboration. Each role has its own system prompt, context, tool whitelist, and token/time/step budget; exceeding it records `budget_exhausted` and aborts.

### The evolution loop

```text
       ┌──────────────────────────────────────────────┐
       │                                              │
  review PR ──► human-confirmed ──► root-cause        │
       ▲          feedback           fingerprint      │
       │                                │             │
       │                                ▼             │
       │                        candidate generation  │
       │                                │             │
       │                                ▼             │
       │              ┌──────────────────────────┐    │
       └── rejected ◄─┤ validation gain          │    │
                      │ + holdout non-regression ├────┘ activate
                      │ + significance           │
                      └──────────────────────────┘
```

Rejected candidates aren't discarded — they enter a version archive along with their per-case scores, to be used for parent selection later. And a batch of feedback is never consumed twice: a separate ledger records which feedback was attempted in which run, and what the verdict was.

Design trade-offs and how they relate to the literature (GEPA, DGM) are in [Evaluation & prompt evolution](evolution.md).

## Docs

| | |
|---|---|
| [Quickstart](quickstart.md) | install, run, submit your first review |
| [Configuration](configuration.md) | LLM provider, modes, budgets |
| [Evaluation & evolution](evolution.md) | the loop, the gates, dataset semantics |
| [GitHub Webhook](github-webhook.md) | wiring up a real repository |
| [HTTP API](api.md) | endpoint reference |
| [Deployment](deployment.md) | Docker / queue / observability |
| [Project status](project-status.md) | capabilities grouped by evidence tier, and known limits |

**On that last document:** it groups capabilities by evidence tier — "measured on the evaluation path" / "unit-tested but off the evaluation path" / "written but unreachable here." The easiest way for a capability list to mislead isn't a false claim; it's listing what was measured alongside what was merely finished, with no way for the reader to tell them apart. If you want to know which numbers were actually produced, how wide the confidence intervals are, and which labels are still untrustworthy, read that one.

## Contributing

See [CONTRIBUTING.md](../CONTRIBUTING.md). The test suite needs no API key and no network.

## License

[MIT](../LICENSE)