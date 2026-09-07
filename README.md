# Agent Forensic Timeline (Concept Prototype)

**An interactive investigation tool concept: reconstructing what a compromised AI agent actually did, and — critically — which agent in a multi-agent chain was the real point of compromise, not just where the damage became visible.**

> ⚠️ **This is an independent concept prototype, not affiliated with, endorsed by, or built using any product, code, or data from Palo Alto Networks or any other named company.** All incident data, agent names, and figures in this demo are fictional and used only to illustrate the workflow.

---

## What problem this addresses

When an AI agent is compromised, most security teams currently have very limited visibility into *what the agent actually decided and why*. A 2026 industry survey found the majority of enterprises had already experienced an AI-agent security incident, while only a minority had real runtime visibility or an audit trail for agent behaviour.

The harder problem sits one level deeper: in a **multi-agent workflow**, a compromised agent's output often gets passed to a *second*, entirely innocent agent, which acts on it in good faith. A monitoring alert typically fires at the second agent — because that's where the visible bad action happened — while the real point of compromise, upstream, stays invisible.

**The idea:** a forensic timeline tool that reconstructs the full decision chain across multiple agents, tags each step against real [MITRE ATLAS](https://atlas.mitre.org/) adversarial techniques, and explicitly identifies "patient zero" — the actual origin of the compromise — even when it's a different agent from the one that triggered the alert.

## What this prototype actually is

A single self-contained HTML file — no backend, no server, no database. It runs entirely in your browser.

It ships with **three distinct, hand-written cases**, each built around a real, named MITRE ATLAS technique:

| Case | Attack pattern | ATLAS techniques used |
|---|---|---|
| INC-2094 | Memory manipulation redirects a document-retrieval call | Memory Manipulation, Tool-Chain Poisoning |
| INC-2101 | A poisoned document intake corrupts an HR agent's config | AI Agent Context Poisoning, Modify AI Agent Configuration |
| INC-2115 | A crafted chat message hijacks an agent's reasoning thread | Thread Injection, Escape to Host |

Hit **"New Case"** to jump between them; each replays as a live investigation sequence, not a static screenshot.

### What it demonstrates
- A reconstructed, step-by-step timeline of agent behaviour, each step tagged with its data source (runtime telemetry, memory snapshot, tool-call log) and, where relevant, its MITRE ATLAS technique.
- Explicit **patient-zero attribution** — visually distinguishing the agent that was actually compromised from the agent whose action merely became visible to monitoring.
- A working **"Export root cause"** action that connects this tool's findings to the [DPDP AutoReport](#) module's compliance drafting — showing how an investigation tool's output should feed directly into regulatory paperwork, not be re-typed by a human in between.
- A real, working **download button** for the investigation report.

### What this prototype deliberately does NOT do
- **No real data or live connection.** All three cases are hand-written, not generated from any real detection system.
- **No backend or database.** Nothing is saved, sent, or persisted beyond your own browser (via localStorage).
- **No real AI-agent monitoring.** Building genuine cross-framework agent telemetry ingestion is a substantial, separate engineering effort — this prototype demonstrates the *investigation workflow* a real version would need, not the underlying detection pipeline.

## How to run it

No build step, no dependencies. Open `index.html` in any modern browser.

## Why this exists

Built alongside [DPDP AutoReport](#) as part of a research and design exercise identifying where a genuine, still-unclaimed gap sits in AI-agent security: cross-agent forensic attribution, distinct from existing single-agent replay tools and from causal-reconstruction features scoped to a single vendor's supported agents. See [`design-decisions.md`](./design-decisions.md) for the reasoning behind each interface choice.

## Sources referenced

- MITRE ATLAS — adversarial technique framework for AI systems, atlas.mitre.org
- MITRE ATLAS agentic AI technique additions (Zenity Labs collaboration, Oct 2025; further additions Feb 2026)

## License

Concept/educational use.
