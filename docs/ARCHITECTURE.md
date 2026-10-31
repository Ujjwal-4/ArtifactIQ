# ArtifactIQ — Architecture

## 1. Overview

```
Browser (UI, external static JS, strict CSP)
   │  fetch() JSON + X-CSRF-Token
   ▼
Flask app (app.py → create_app)
   ├── web/pages.py      HTML routes (dashboard, cases, case workspace, targeted, acquisition, settings)
   ├── web/api.py        /api JSON routes (all state changes)
   ├── services/         custody, evidence, parsing, timeline, graph, attack,
   │                     prediction, risk, explanation, phases, reports
   ├── parsers/          evtx, csv_events, json_events, browser_sqlite,
   │                     usb_setupapi, registry(.reg text + .HIVE via regipy)
   ├── acquisition/live  opt-in, targeted, audited collectors
   ├── util/             validation, pathsafety, hashing, timestamps, audit, security
   └── SQLite (stdlib sqlite3, no ORM) + evidence store on disk (randomized names)
```

No ORM, no message queue, no external model service in the default
configuration. A case runs entirely offline.

## 2. Data model (schema.sql highlights)

- **cases** — case_number (unique pattern-validated), title, investigator,
  mode (`full` | `targeted`), capability, status.
- **evidence** — one row per preserved copy: randomized `stored_name`
  (client path is never used for storage), relative `data_path` inside a
  controlled store root, `sha256` of the preserved copy, `media_type`,
  `acquisition_method`, `verify_status` (unverified/verified/mismatch/error/retained).
- **custody_records** — append-only GLOBAL hash chain: each row stores
  `prev_hash` (hash of the immediately preceding record, any case), its own
  `record_hash` (SHA-256 over the row fields), seq, actor, action, reason.
  Deleting or editing any row anywhere makes subsequent chain checks fail.
- **events** — normalized timeline rows per parsed evidence; ISO-8601 `ts_utc`
  only when the artifact itself declared UTC/offset, plus `ts_original`,
  `ts_precision`, `ts_source`. Missing timestamps stay missing.
- **parser_runs, findings, attack_mappings, branches, risk_assessments,
  entities/relationships, acquisition_sessions(+artifacts), phase_runs,
  audit_events, reports**.

## 3. Evidence integrity model — and its honest limits

- Intake: stream upload to a temp file in the controlled work dir, refuse
  empty/over-limit files, then preserve as `<store>/<prefix>/<random>.<ext>`
  and compute SHA-256 over the preserved bytes.
- `verify` recomputes SHA-256 and compares with the recorded value; result is
  appended to the custody chain.
- `remove` parks the file in a trash folder, marks the row `retained`, and appends
  `evidence_removed` to the ledger. Files are never silently destroyed.
- **Honest caveat (by design):** a hash matches the *preserved copy inside the
  store*. It cannot prove what happened on the original source system, and
  the ledger, while hash-chained, lives in the same SQLite file — it is
  tamper-*evident*, not tamper-*proof*.

## 4. Custody chain semantics

- `custody.append(action, case_id, evidence_id, actor=, reason=)` — one global chain.
- `custody.verify()`—recomputes hashes for the whole chain; `verify(case_id=…)`
  / `verify(evidence_id=…)` re-check only the relevant records but validate them
  against the full global narration of the chain (predecessor links).
- Any case/evidence delete keeps the ledger intact; the case row (not the
  ledger) is what goes.

## 5. Deterministic analysis (no magic)

- **Findings/ATT&CK (`services/attack.py`)** — versioned rule set
  `attack-rules/2025a…` over normalized event types. Rules reference concrete
  event ids; every mapping names its rule version and evidence ids.
- **Branches (`services/prediction.py`)** — rules B1–B7 produce a *question*,
  never a conclusion, with `priority = <published formula>` and the calculation
  stored in `priority_calc`. Investigators confirm/dismiss; decisions are
  recorded with `decision_by="investigator-authoritative"`.
- **Risk (`services/risk.py`)** — `score = min(100, S*16 + T*14 + C*10 + A*10)`
  with S = max finding severity, T = ATT&CK tactic diversity, C = breadth
  (hosts/users), A = analysis completeness; all inputs and versions stored in
  `inputs` JSON.

## 6. Web security posture

- Server-side CSRF (`X-CSRF-Token` header or `csrf_token` field) on all
  state-changing routes; session cookie HttpOnly, SameSite=Lax.
- Strict CSP: `script-src 'self'` — **no inline scripts anywhere**. Jinja-built
  URLs are passed to JS via `<script type="application/json" id="cfg-…">`
  blocks (non-executable) that the external JS reads.
- `style-src 'self' 'unsafe-inline'` is deliberately allowed for app-controlled
  static style attributes (layout, not content injection).
- Uploads: extension allow-list, size limit, duplicate-content detection,
  `safe_original_name()` sanitization, traversal-proof storage naming,
  `resolve_within()` containment for every stored path read.
- Security headers: `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`,
  `Referrer-Policy`, CSP. Host binding defaults to loopback.

## 7. Parsing design

Each parser: streaming/working-copy approach, per-record budget + global event
cap + wall-clock timeout, and **honest failure**: malformed input yields
`failed`/`unsupported` parser runs with reasons — no invented events, and
placeholder values like `-` are never copied into normalized fields.

Timestamp rule: `ts_utc` is stored only when the artifact declares UTC or an
offset (e.g. trailing `Z`, evtx SystemTime). Otherwise the original string and
precision (e.g. `csv_timestamp_no_tz`) are kept and the timeline orders with
`unknown_ts_count` surfaced — never "assume local".

## 8. Live acquisition

Disabled by default (`ARTIFACTIQ_ALLOW_LIVE` off). When enabled, a session is
created explicitly, gated by per-source capabilities, permission-gated in the
UI, and audited. Collectors write a session manifest of exactly the files they
read. Access-denied → honest `denied` status, no silent skip. This is a
session file on the endpoint: the tool does NOT claim zero footprint.
