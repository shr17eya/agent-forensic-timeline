# Design decisions

## 1. Three cases, three different real ATLAS techniques — not one case repeated

An early version shipped with a single fixed case. That made the tool feel like a script, not a capability — and made it impossible to tell whether the underlying idea generalised. Three cases, each built around a genuinely different, verified MITRE ATLAS technique, exist to demonstrate the *pattern* is real and repeatable, not a one-off scripted demo. This doesn't make the tool "live" — the cases are still hand-written — but it proves the reasoning behind the tool works across more than one scenario.

## 2. "Patient zero" is the actual point of the tool, not a decorative label

Every case is deliberately structured so the agent that triggers the monitoring alert is *not* the agent that was actually compromised. This is the core design bet: existing single-agent replay and causal-reconstruction tools investigate the agent connected to the alert. This prototype exists to show why that's insufficient in a multi-agent workflow, and what a tool that gets this right should surface instead.

## 3. Visual language: a case board, not a SaaS dashboard

This tool and the DPDP AutoReport module serve different jobs — one is regulatory paperwork, the other is active investigation — and were deliberately given different visual languages to match. A detective's case-board metaphor (pinned evidence, connecting string, stamped attribution) was chosen because forensic investigation is fundamentally about piecing together a sequence of evidence to reach a conclusion, which is what the metaphor is built around, not decoration for its own sake.

## 4. The "Export root cause" button, and why it's a one-way, visible action

This button doesn't silently sync data anywhere — clicking it shows an explicit confirmation ("✓ Exported to [case] draft"). This exists to make a specific point concrete: an investigation tool's findings should flow into compliance/reporting tooling as a traceable, deliberate action, not an invisible background sync a human has to trust blindly.

## 5. Local persistence, scoped to what's actually worth remembering

Only two things persist across a refresh: which case you're viewing, and whether you've exported it. The investigation sequence itself always replays fresh rather than restoring mid-animation, because restoring a partially-played animation state adds real complexity for no real benefit — a returning user should see the finished picture, not a frozen half-played scene.

## Known limitations (not fixed, and why)

- **No live agent telemetry ingestion.** Real cross-framework agent monitoring (LangChain, AutoGen, custom MCP servers, vendor copilots each logging differently) is a substantial, separate engineering problem — not something a static prototype can responsibly simulate as "working."
- **Attribution logic is scripted, not inferred.** In this prototype, "patient zero" is a fact I wrote into each case, not a conclusion the tool derived from raw data. A real version would need genuine causal-graph reasoning across agent handoffs — the hardest, least-solved part of this whole space.
- **No connection to a real DPDP AutoReport instance.** The "Export" action confirms visually but doesn't actually transfer data anywhere, for the same reasons covered in that project's own documentation — no live backend exists to receive it.
