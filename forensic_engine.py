#!/usr/bin/env python3
"""
Agent Forensic Timeline — Python Engine
=========================================
A standalone, real, working companion to the HTML mockup. This does NOT
replace the browser tool — it's a second, independent implementation of
the same idea, useful for:

  1. Command-line analysis of any case (no browser needed)
  2. Validating that every MITRE ATLAS technique name used is real
  3. Generating the same investigation report as a plain text file
  4. Proof that the attribution logic works outside a single HTML file

Concept prototype only. Not affiliated with Palo Alto Networks.
"""

import json
import sys
import argparse
from pathlib import Path

# ---------------------------------------------------------------------------
# The three example cases — same scenarios as the HTML tool, kept unchanged.
# This is INPUT DATA ONLY. No conclusions are stored here.
# ---------------------------------------------------------------------------
EXAMPLES = [
    {
        "id": "INC-2094",
        "label": "Vendor KYC leak",
        "events": [
            {"actor": "Vendor-Onboarding Agent", "time": "09:11:02",
             "desc": "Receives routine task: \"Fetch latest KYC documents for Vendor #4471.\"",
             "flagged": False, "tags": [["source", "Runtime Telemetry"]]},
            {"actor": "Vendor-Onboarding Agent", "time": "09:11:04",
             "desc": "Loads a cached context note from long-term memory. The note was silently altered in a prior session.",
             "flagged": True, "tags": [["atlas", "Memory Manipulation"], ["source", "Memory Snapshot"]]},
            {"actor": "Vendor-Onboarding Agent", "time": "09:11:05",
             "desc": "The poisoned context silently redirects the document-retrieval tool call to an unauthorised external endpoint.",
             "flagged": True, "tags": [["atlas", "Tool-Chain Poisoning"], ["source", "Tool-Call Log"]]},
            {"actor": "Vendor-Onboarding Agent", "time": "09:11:06",
             "desc": "Returns a normal-looking \"success\" response. Nothing in the agent's own tool-call log indicates anything went wrong.",
             "flagged": True, "tags": [["source", "Tool-Call Log"]]},
            {"actor": "Procurement Approval Agent", "time": "09:11:09",
             "desc": "Receives the already-compromised output as trusted input and approves the vendor record update.",
             "flagged": False, "tags": [["source", "Runtime Telemetry"]]},
            {"actor": "Cortex XSIAM", "time": "09:14:00",
             "desc": "Flags anomalous outbound data volume from the procurement workflow.",
             "flagged": True, "tags": [["source", "XSIAM"]]},
        ],
    },
    {
        "id": "INC-2101",
        "label": "HR payroll redirect",
        "events": [
            {"actor": "HR Onboarding Agent", "time": "14:02:11",
             "desc": "Receives routine task: \"Process new-hire intake packet for Employee #2207.\"",
             "flagged": False, "tags": [["source", "Runtime Telemetry"]]},
            {"actor": "HR Onboarding Agent", "time": "14:02:14",
             "desc": "A resume attachment contains hidden instructions that alter the agent's operating context.",
             "flagged": True, "tags": [["atlas", "AI Agent Context Poisoning"], ["source", "Document Parser Log"]]},
            {"actor": "HR Onboarding Agent", "time": "14:02:16",
             "desc": "The altered context modifies the agent's own configuration, skipping bank-account verification.",
             "flagged": True, "tags": [["atlas", "Modify AI Agent Configuration"], ["source", "Config Diff"]]},
            {"actor": "HR Onboarding Agent", "time": "14:02:17",
             "desc": "Returns a normal-looking \"intake complete\" response. Nothing in the logs indicates its configuration changed.",
             "flagged": True, "tags": [["source", "Runtime Telemetry"]]},
            {"actor": "Payroll Sync Agent", "time": "14:02:20",
             "desc": "Receives the already-compromised record as trusted input and syncs an unverified bank account.",
             "flagged": False, "tags": [["source", "Runtime Telemetry"]]},
            {"actor": "Cortex XSIAM", "time": "14:05:40",
             "desc": "Flags an anomalous first-payroll-cycle destination-account change.",
             "flagged": True, "tags": [["source", "XSIAM"]]},
        ],
    },
    {
        "id": "INC-2115",
        "label": "Support sandbox escape",
        "events": [
            {"actor": "Support Copilot Agent", "time": "19:47:03",
             "desc": "Receives routine task: \"Respond to customer chat, ticket #88291.\"",
             "flagged": False, "tags": [["source", "Runtime Telemetry"]]},
            {"actor": "Support Copilot Agent", "time": "19:47:06",
             "desc": "A crafted customer message is treated as a system-level instruction inside the agent's reasoning thread.",
             "flagged": True, "tags": [["atlas", "Thread Injection"], ["source", "Chat Transcript"]]},
            {"actor": "Support Copilot Agent", "time": "19:47:08",
             "desc": "The injected instruction causes the agent to step outside its sandboxed tool environment and read local session files.",
             "flagged": True, "tags": [["atlas", "Escape to Host"], ["source", "Sandbox Log"]]},
            {"actor": "Support Copilot Agent", "time": "19:47:09",
             "desc": "Returns a normal-looking chat reply. Nothing in the visible conversation log indicates a sandbox escape occurred.",
             "flagged": True, "tags": [["source", "Chat Transcript"]]},
            {"actor": "Ticket Routing Agent", "time": "19:47:13",
             "desc": "Receives the already-compromised session data and forwards it as trusted input to a support queue.",
             "flagged": False, "tags": [["source", "Runtime Telemetry"]]},
            {"actor": "Cortex XSIAM", "time": "19:49:50",
             "desc": "Flags an unusual file-read pattern originating from the copilot's sandbox.",
             "flagged": True, "tags": [["source", "XSIAM"]]},
        ],
    },
]

# ---------------------------------------------------------------------------
# The real, verified MITRE ATLAS technique names this project may reference.
# Sourced from atlas.mitre.org. Update this list if MITRE adds more.
# ---------------------------------------------------------------------------
REAL_ATLAS_TECHNIQUES = {
    "Memory Manipulation",
    "Thread Injection",
    "Modify AI Agent Configuration",
    "AI Agent Context Poisoning",
    "Tool-Chain Poisoning",
    "Escape to Host",
    "Publish Poisoned AI Agent Tool",
    "LLM Prompt Injection",
}


def compute_attribution(events: list[dict]) -> dict:
    """
    The core engine. Given a chronological list of events, work out who
    'patient zero' is — NOT the agent that triggered the alert, but the
    agent whose action was the actual first point of compromise.

    Rule: the earliest event marked flagged=True is the point of compromise.
    If a later, different, unflagged actor acted on that corruption before
    detection, name them explicitly as the one who looked responsible but
    wasn't.
    """
    if not events:
        return {"text": "No events to analyze.", "patient_zero": None, "alert_actor": None}

    patient_zero_event = next((e for e in events if e["flagged"]), None)
    alert_event = events[-1]

    if patient_zero_event is None:
        return {
            "text": "No flagged events found in this timeline — nothing here indicates a point of compromise.",
            "patient_zero": None,
            "alert_actor": alert_event["actor"],
        }

    pz_index = events.index(patient_zero_event)
    propagator_event = next(
        (e for e in events[pz_index + 1:] if not e["flagged"] and e["actor"] != patient_zero_event["actor"]),
        None,
    )

    atlas_tags = [t[1] for t in patient_zero_event.get("tags", []) if t[0] == "atlas"]
    technique = atlas_tags[0] if atlas_tags else "an unspecified technique"

    text = f"Patient zero is {patient_zero_event['actor']}'s {technique} at {patient_zero_event['time']}."
    if propagator_event and propagator_event["actor"] != patient_zero_event["actor"]:
        text += (
            f" Not {propagator_event['actor']}, where the breach first became visible "
            f"through {alert_event['actor']}."
        )
        text += " A tool that only looked at where the alert fired would have investigated the wrong agent."
    else:
        text += " No separate propagating agent was involved."

    return {
        "text": text,
        "patient_zero": patient_zero_event["actor"],
        "alert_actor": alert_event["actor"],
    }


def find_case(case_id: str) -> dict | None:
    return next((c for c in EXAMPLES if c["id"].lower() == case_id.lower()), None)


def cmd_list(_args):
    print(f"{'ID':<12} {'Label':<30} {'Events'}")
    print("-" * 55)
    for c in EXAMPLES:
        print(f"{c['id']:<12} {c['label']:<30} {len(c['events'])}")


def cmd_analyze(args):
    case = find_case(args.case)
    if not case:
        print(f"No case found with ID '{args.case}'. Run 'list' to see available cases.", file=sys.stderr)
        sys.exit(1)

    print(f"CASE FILE — {case['id']} — {case['label']}")
    print("=" * 50)
    for ev in case["events"]:
        flag = "  [FLAGGED]" if ev["flagged"] else ""
        print(f"[{ev['time']}] {ev['actor']}{flag}")
        print(f"  {ev['desc']}")
        for ttype, ttext in ev.get("tags", []):
            print(f"    - ({ttype}) {ttext}")
        print()

    result = compute_attribution(case["events"])
    print("ATTRIBUTION (computed):")
    print(f"  {result['text']}")

    if args.out:
        lines = [f"CASE FILE — {case['id']} — {case['label']}", "=" * 50, ""]
        for ev in case["events"]:
            lines.append(f"[{ev['time']}] {ev['actor']}")
            lines.append(ev["desc"])
            lines.append("")
        lines.append("Attribution (computed):")
        lines.append(result["text"])
        lines.append("")
        lines.append("--- Generated by Agent Forensic Timeline (Python engine) — not a real system ---")
        Path(args.out).write_text("\n".join(lines), encoding="utf-8")
        print(f"\nReport written to {args.out}")


def cmd_validate(_args):
    print("Validating every MITRE ATLAS technique reference against the real framework...\n")
    problems = 0
    checked = 0
    for case in EXAMPLES:
        for ev in case["events"]:
            for ttype, ttext in ev.get("tags", []):
                if ttype != "atlas":
                    continue
                checked += 1
                if ttext in REAL_ATLAS_TECHNIQUES:
                    print(f"  OK   {case['id']}  \"{ttext}\"")
                else:
                    print(f"  FAIL {case['id']}  \"{ttext}\"  <-- not a recognised ATLAS technique name")
                    problems += 1

    print(f"\nChecked {checked} technique reference(s), {problems} problem(s) found.")
    if problems:
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(
        description="Agent Forensic Timeline — standalone Python engine (concept prototype, not a real system)"
    )
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("list", help="List all available cases").set_defaults(func=cmd_list)

    p_analyze = sub.add_parser("analyze", help="Analyze a case and print its computed attribution")
    p_analyze.add_argument("case", help="Case ID, e.g. INC-2094")
    p_analyze.add_argument("--out", help="Also write the report to this .txt file", default=None)
    p_analyze.set_defaults(func=cmd_analyze)

    sub.add_parser(
        "validate", help="Check every ATLAS technique name used against the real MITRE ATLAS list"
    ).set_defaults(func=cmd_validate)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
