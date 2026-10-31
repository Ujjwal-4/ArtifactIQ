# ArtifactIQ — HTTP API

Base path: `/api`. All state-changing requests require CSRF (session-scoped
token; send as header `X-CSRF-Token: <token>` or as field `csrf_token`).
All responses are JSON `{"ok": true, ...}` or `{"ok": false, "error": ...}`
with HTTP 400/403/404/409 as appropriate.

## Cases

| Method | Path | Notes |
|---|---|---|
| POST | `/api/cases` | create case. JSON or form. Validated fields: `title` (3-200), `investigator` (2-80), `case_number` (`^[A-Za-z0-9][A-Za-z0-9_.-]{2,40}$`, auto-generated if omitted), `description`, `scope`, `authorization`, `mode` (`full`/`targeted`; targeted requires `capability`), `capability`. Returns `{case_id}`. |
| GET | `/api/cases` | list all cases |
| GET | `/api/cases/<id>` | one case; 404 JSON if unknown |
| POST | `/api/cases/<id>/update` | metadata update (validated subset); custody `case_updated` |
| POST | `/api/cases/<id>/archive` | toggle archive; custody `case_archive_toggled` |
| POST | `/api/cases/<id>/delete` | **requires** JSON `{"confirm": "<case_id>:DELETE"}`. Removes the case row; evidence copies already parked to trash; custody ledger is kept. |

## Evidence

| Method | Path | Notes |
|---|---|---|
| POST | `/api/cases/<id>/evidence` | multipart `file` (allow-listed ext), optional `media_type`, `source_desc`, `notes`, `acquisition_method=snapshot`, `source_hash` (16/40/64 hex). Computes SHA-256 at intake; duplicate content in the same case is refused with 400. |
| GET | `/api/cases/<id>/evidence` | list evidence rows |
| POST | `/api/evidence/<id>/verify` | recompute SHA-256. Returns `{ok, result/status (verified/mismatch/error), recorded, computed}` and appends to custody. |
| POST | `/api/evidence/<id>/remove` | park copy to trash retention; row stays with `verify_status=retained`; custody `evidence_removed`. |

## Custody

| Method | Path | Notes |
|---|---|---|
| GET | `/api/cases/<id>/custody` | records for the case + `verification` `{ok, issue, records_checked, records_total, head_hash, algorithm}` |
| POST | `/api/custody/<evidence_id>/verify_evidence_chain` | chain check scoped to one evidence |

## Parsing / timeline / events

| Method | Path | Notes |
|---|---|---|
| POST | `/api/cases/<id>/parse` | run registered parsers over registered evidence (budget/time-limited). Returns `runs[]`. |
| GET | `/api/cases/<id>/parser_runs` | run history with statuses (failed/unsupported are honest, not hidden) |
| GET | `/api/cases/<id>/timeline` | paged events; facets; `unknown_ts_count` |
| GET | `/api/cases/<id>/timeline/clusters` | time clusters |
| GET | `/api/cases/<id>/timeline/export` | CSV export (comment header, column list) |
| GET | `/api/events/<event_id>` | one event + source evidence info |

## Analysis

| Method | Path | Notes |
|---|---|---|
| POST | `/api/cases/<id>/analyze` | rebuild graph + ATT&CK mappings (deletes-stale, recreates; versioned rules) |
| GET | `/api/cases/<id>/graph` | `{graph:{nodes,edges}, hops}` |
| GET | `/api/cases/<id>/attack` | mappings + rule version |
| POST | `/api/cases/<id>/branches/generate` | regenerate branches B1–B7 (DELETEs + recreates; refetch ids before deciding) |
| GET | `/api/cases/<id>/branches` | with `priority`, `priority_calc` (formula + inputs), `evidence_ids`/`missing_evidence` |
| POST | `/api/branches/<id>/decide` | `{"status": "confirmed"/"dismissed"/"open", "note": ...}`; unknown statuses are rejected (400) |
| POST | `/api/cases/<id>/risk` | recompute risk (deterministic formula, all inputs stored) |
| GET | `/api/cases/<id>/risk` | latest stored assessment (`inputs` JSON with every component) |
| GET | `/api/cases/<id>/explanation` | grounded narrative merged at top level (`sentences`, `cites`, counts) + `explanation` object |
| POST | `/api/cases/<id>/explanation/llm` | 409 unless `ARTIFACTIQ_LLM_ENABLED=1` and `ARTIFACTIQ_LLM_URL` set; only derived narrative text is sent |

## Phases / acquisition / reports / audit

| Method | Path | Notes |
|---|---|---|
| GET | `/api/cases/<id>/phases` | phase status map per case |
| POST | `/api/cases/<id>/phases/refresh` | recompute; p06 stays `blocked` (no disk-image engine) |
| GET | `/api/acquisition/sources` | declared live sources + whether live is enabled |
| POST | `/api/cases/<id>/acquisition/sessions` | create opt-in targeted session; creates a session file; must be confirmed per source |
| POST | `/api/acquisition/<session>/cancel` | cancel an acquisition session |
| GET | `/api/cases/<id>/acquisition` | sessions + collected artifacts |
| POST | `/api/cases/<id>/reports` | `{"kind": "html"/"pdf"/"findings"/"manifest"/"custody"}`; returns `{report}` |
| GET | `/api/cases/<id>/reports` | report history |
| GET | `/api/reports/<report_id>/download` | file download |
| GET | `/api/audit` | audit event list |
| POST | `/api/demo/load` | build a fresh fully-labeled `SYNTHETIC` demo case (timestamped `DEMO-…` number), never merged with real case data |
