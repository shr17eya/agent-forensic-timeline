# forensic_engine.py

A standalone Python companion to the Agent Forensic Timeline HTML tool. This is a **second, independent implementation** of the same attribution logic — real, tested, working code, separate from the browser version, added without touching or risking what's already in `index.html`.

## Why this exists
The HTML tool computes attribution in JavaScript, in the browser. This does the exact same reasoning in Python, from the command line — proving the underlying logic isn't tied to one file or one language, and giving three things the browser version can't:

1. **A validator** — checks every MITRE ATLAS technique name used against a real reference list, catching typos or invented names automatically.
2. **A CLI report generator** — produces the same investigation report without opening a browser.
3. **Independent verification** — since it's a second implementation of the same idea, both agreeing confirms the logic itself is sound, not just one file's copy of it.

## Usage

```bash
python3 forensic_engine.py list
python3 forensic_engine.py analyze INC-2094
python3 forensic_engine.py analyze INC-2094 --out report.txt
python3 forensic_engine.py validate
```

## What it deliberately does not do
No real data, no live connection to any monitoring system — same honest scope as the HTML tool. This reasons over the same three fictional example cases, not real telemetry.
