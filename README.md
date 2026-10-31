# ArtifactIQ 2.0.0 — AI-Powered Predictive Digital Forensic Investigation Platform

ArtifactIQ is a local, single-investigator forensic case management and analysis
platform for Windows artifact triage. It ingests evidence **copies** (never
touching originals), hashes and hashes-chains a custody ledger, parses the
artifacts into a normalized timeline, and produces **explainable** rule-backed
findings, ATT&CK mappings, investigation branches, a risk score, and reports.

Everything is designed to be **honest**:

- Demo data is labeled `SYNTHETIC` and never mixed with real evidence.
- Missing capabilities are reported as `blocked` / `unsupported`, never faked.
- Predictions are deterministic rules with visible formulas, inputs, and rule
  versions — no invented facts, no hidden model magic.
- The app does not claim to be "zero-footprint"; live acquisition is opt-in,
  targeted, permission-gated and audited, and it plainly writes a session file
  of exactly what it collected.

## Feature summary (12 phases)

| Phase | What it does | Status in v2.0.0 |
|---|---|---|
| p01 Cases | case numbers, metadata, archive/delete (retention-aware) | working |
| p02 Acquisition plan | plan + authorization notes per case | working |
| p03 Acquisition | offline upload, optional targeted live collection | working |
| p04 Parsing | JSON, CSV, `.evtx`, browser SQLite, USB `setupapi.dev.log`, registry `.reg`/`.HIVE` | working (HIVE needs optional regipy) |
| p05 Custody | SHA-256 intake hash, append-only hash-chained ledger, verification | working |
| p06 Disk image | TSK-based image/deleted-file analysis | **blocked** — no disk-image engine present; honest, not implemented |
| p07 Timeline | unified timeline, facets, search, CSV export | working |
| p08 Graph + ATT&CK | entity graph and MITRE ATT&CK v15 mapping | working (local mapping table) |
| p09 Branches | predictive next-step branches with priority formulas + confirm/dismiss | working |
| p10 Risk | deterministic S/T/C/A score with published formula | working |
| p11 Explanation | grounded narrative; optional external LLM assist | working |
| p12 Reports | HTML, PDF, findings CSV, manifest JSON, custody JSON | working |

## Quick start (Windows)

```bat
rem 1) Python 3.11+ (tested with 3.13)
python -m venv .venv
.venv\Scripts\python -m pip install -r requirements.txt

rem 2) choose a data directory (keeps DB + evidence store outside the code)
set ARTIFACTIQ_DATA_DIR=D:\aiq_data
set ARTIFACTIQ_SECRET_KEY=change-me-to-a-long-random-string

rem 3) run
.venv\Scripts\python app.py
rem -> http://127.0.0.1:5555
```

The first start creates the SQLite schema (`artifactiq.db`) and the evidence
store (randomized storage names; originals are never written).

**Load synthetic demo:** Dashboard → `Load Demo Case`. This builds a fully
labeled `SYNTHETIC` case (events, USB log, registry export, browser SQLite)
and runs the whole pipeline end-to-end.

## Offline / live behavior

- Default = **offline import** only.
- Setting `ARTIFACTIQ_ALLOW_LIVE=1` enables the live-acquisition workbench.
  It is **explicit, targeted, permission-gated and audited**. It writes an
  acquisition-session file reporting exactly what was collected. There is no
  claim of "zero footprint" anywhere.
- Access-denied during live collection is reported as `denied` with the
  reason — never silently skipped.

## Tests

```bat
.venv\Scripts\python -m pytest . 
rem -> 36 passed (unit: parsers/custody/analysis; integration: full pipeline;
rem            security: CSRF, traversal, tamper detection, headers)
```

Tests run against throwaway temp directories (`ARTIFACTIQ_DATA_DIR` is
redirected for the session); they never touch real or demo data.

## Documentation

- `docs/ARCHITECTURE.md` — design, data model, custody chain, CSP approach
- `docs/API.md` — every `/api` endpoint
- `docs/DEMO.md` — what the synthetic demo contains and proves
- `docs/PHASES.md` — the 12 phases and their honest status rules
- `docs/TROUBLESHOOTING.md` — port/env/deps problems
- `docs/LIMITATIONS.md` — everything this tool does NOT do (read this)
- `docs/VERIFICATION.md` — a checklist you can run to verify a build

## Safety and legal notice

Use only on systems and data you are authorized to investigate. Evidence
integrity claims apply to **preserved copies** inside the evidence store; the
tool cannot prove anything about sources outside its custody.