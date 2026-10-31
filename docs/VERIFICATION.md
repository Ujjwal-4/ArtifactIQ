# Verification checklist — ArtifactIQ 2.0.0

Every step below was executed against this exact tree
(Python 3.13.2, Flask 3.0.3, Windows 11, venv from `ArtifactIQ\.venv`).

## 1. Environment
- [x] `python -m pip install -r requirements.txt` — Flask 3.0.3, Werkzeug 3.1.9,
      reportlab 5.0.1, python-evtx 0.8.1, regipy 6.5.0, pytest 9.0.3 all import.
- [x] No secrets hardcoded: `grep -r "SECRET" artifactiq/` → only env reads.

## 2. Tests (run from `ArtifactIQ2/`)
```bat
set ARTIFACTIQ_DATA_DIR=%TEMP%\aiq_pytest_final
.venv\Scripts\python -m pytest . -q
```
- [x] Result: **36 passed** (exit 0), zero failures:
  - unit parsers (10), custody (4), analysis (10)
  - integration pipeline (2), security (10)
  - Verified assertions include: CSV username mapping, USB fractional-second
    timestamps, no-header CSV error, browser download T0+10min regression,
    custody tamper detection, risk formula exactness, CSRF, traversal
    sanitization, duplicate-content refusal, retention-aware delete.

## 3. End-to-end demo (smoke)
- [x] `SMOKE OK`: 5 parser runs completed (27 events), 8 findings,
      8 ATT&CK mappings with rule versions, 7 evidence-grounded branches with
      priority formulas, risk 100/critical, custody `verify=true`,
      deliberate tamper detection works, demo case rebuild produces a fresh
      `DEMO-…-<hhmmss>` case number, targeted demo case works.
- [x] `api_smoke`: 22 endpoint checks + 5 report kinds → all HTTP 200.
- [x] `page500`: 17 case tabs + top-level pages -> all 200; static tab JS 200.

## 4. Browser (live server on 127.0.0.1:5555)
- [x] Dashboard, Cases, and all 10 case tabs load with **zero console errors**.
- [x] Timeline tab: 17 timestamped events rendered.
- [x] ATT&CK tab: T1078/T1543.003/T1053.005/T1070.002/T1059.001/T1091 visible.
- [x] Risk tab: critical band data rendered from API.
- [x] CSP header honored: `script-src 'self'` with **no inline scripts**;
      configuration travels via `<script type="application/json" id="cfg-…">`.
- [x] Acquisition run re-tested live: `POST /api/cases/<id>/acquisition/sessions`
      returns **200** (an earlier release 500-ed on `ok(session_id=…, **res)`
      name collision — fixed; `res["session_id"]` is dropped by the route).
- [x] Activity timestamps (case created, phase runs, custody ledger,
      acquisition, audit, cases table, reports, settings) render in the
      **viewer's local time** while stored as UTC; artifact event timestamps
      (timeline/capability preview) stay UTC-declared with explicit labels.
- [x] Overview phase counter explains itself: `8/12` plus a note listing
      `awaiting optional input / blocked / not started yet` counts.
- [x] Full cases no longer show a "Targeted Result" tab; a manual
      `/cases/<id>/capability` URL redirects to overview (no 404).
- [x] Targeted capability tab E2E in browser: register artifact → SHA-256
      intake → capability auto-runs → run row `browser_sqlite completed, 6
      events` + result preview renders (extensionless Chrome `History` file
      is treated as `browser_sqlite` via the capability media hint).
- [x] **Phase 6 live engine run** (pytsk3 4.15.0 prebuilt wheel): demo case
      overview shows **12/12**; Evidence tab shows the disk-image panel with
      run row `completed · 4 files · 1 dir · FAT16` and the file listing
      (`/README.TXT`, `/SYNTHETI.TXT`, `/DOWNLOAD/TOOLPACK.EXE`).
- [x] `GET/POST /api/cases/<id>/image(/analyze)` verified; analysis is
      read-only (sha256 identical before/after), audit row `image_analyzed`
      appended, and `pytest -q` = **43 passed** (7 new disk-image/phase tests)
      on the same venv.

## 5. Honesty checks
- [x] p06_image degrades honestly: `blocked` when no image is in scope or when
      pytsk3 is not installed (with the install hint); `completed` only after a
      real engine walk of a registered image.
- [x] Demo data carries SYNTHETIC labels; `Load Demo Case` never merges into
      existing cases (fresh `DEMO-YYYY-NNN-hhmmss`).
- [x] `-` placeholders from CSVs are stripped, never stored as values.
- [x] Failed/unsupported parser runs surface reasons in the UI and API.
- [x] No "zero-footprint" claim anywhere; live acquisition writes a session
      file and is permission-gated/audited.

## 6. Packaging
- [x] `ArtifactIQ2_v2.0.0.zip` — source + tests + docs + requirements +
      `.env.example` (no instance data, no DB file, no synthetic fixtures).
