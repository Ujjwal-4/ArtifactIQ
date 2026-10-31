# Troubleshooting

## Port already in use (5555)

A previous run may still hold the port. On Windows:

```powershell
Get-NetTCPConnection -LocalPort 5555 -State Listen | Select LocalPort,OwningProcess
Stop-Process -Id <PID> -Force
```

or set `ARTIFACTIQ_PORT=5556`.

## 400 on every POST from scripts/tests

CSRF is enabled by default (`ARTIFACTIQ_CSRF=1`). Fetch the session cookie and
send `X-CSRF-Token: <same token>` (the token is also exposed to the UI through
the `csrf_token` field hidden inputs use).

## regipy / python-evtx "unsupported"

`regipy` and `python-evtx` are optional. Without them, `.HIVE` and `.evtx`
parsing return honest `unsupported` runs (the evidence copy stays intact in
the store). Install via `pip install -r requirements.txt` to enable them.

## Disk image (Phase 6) stays "blocked" — how to open it

Blocked means one of three things; the phase detail says which:

1. **No disk image registered in the case** — phase 6 is "when applicable".
   Register an image on the Evidence tab with media type `disk_image`
   (extensions `.raw .dd .img .e01 .vhd .vhdx .001` are auto-detected).
2. **Engine not installed** — install The Sleuth Kit binding into the project
   venv (a prebuilt wheel exists for CPython 3.13 on Windows), then restart
   the server:
   ```
   .venv\Scripts\python.exe -m pip install pytsk3
   ```
3. **Image registered but not yet analyzed** — open the Evidence tab and press
   **Analyze disk image(s) now**. The panel lists partitions/filesystems, and
   the per-file listing (path, kind, size, mtime). `E01`/VHD support depends
   on the TSK libraries bundled in the wheel; unsupported containers fail the
   run with the engine's own error text in the table (never silently).
   Analysis is **read-only**: the preserved copy is SHA-256 verified before and
   after every run.

## "An identical file is already registered in this case"

That's the duplicate-content guard (bytes match something already registered
in the case). Intentional; use a different file or a different case.

## Case delete returns 400

Deletion requires the explicit confirm token: `POST /api/cases/<id>/delete`
with JSON `{"confirm": "<case_id>:DELETE"}`. This is by design so evidence can
be parked to retention deliberately.

## Database schema errors after upgrading the code

The schema is created lazily and versioned in `meta.schema_version`. If you
switched data directories between versions, ensure `ARTIFACTIQ_DATA_DIR`
points to the intended location; or delete/initialize a fresh SQLite file for
test environments only (never drop tables holding real custody history).

## Chinese path / OneDrive directory

The app handles unicode data dirs fine (tests run under a
OneDrive-центic temp path). If `python` is not on PATH, invoke your venv
interpreter by full path, e.g.
`%PATH_TO%\ArtifactIQ\.venv\Scripts\python.exe app.py`.

## Live acquisition page says disabled

Set `ARTIFACTIQ_ALLOW_LIVE=1` before starting `app.py`. It stays permission-
gated and audited;Collector results are written to the acquisition session
file and the custodian ledger.

## Report PDF blank/missing

PDF rendering needs `reportlab` (in requirements). If it is absent the API
reports the run as failed/unsupported rather than producing a fake file.

## Timestamps look off by a few hours

Activity timestamps (case created, phase runs, custody ledger, acquisition,
audit, reports) are **stored in UTC** and rendered in the **viewer's local
time** by the UI. Artifact event timestamps (timeline, capability preview)
are the timestamps declared inside the evidence itself and stay labeled UTC;
events without a trustworthy UTC timestamp are surfaced as `unknown` rather
than guessed. If a wall-clock time looks shifted, compare against the UTC
value in the API JSON, not the raw string.

## "Targeted Result" tab missing (full case) or capability run shows nothing

- The "Targeted Result" tab exists **only for targeted cases**; on a full
  case the tab is hidden and a manual `/cases/<id>/capability` URL
  redirects to the overview.
- A targeted capability needs an artifact first. The capability tab has a
  built-in `Register artifact` form (extensions pre-filtered per
  capability; an extensionless Chrome/Edge `History` file is treated as
  `browser_sqlite`). After registration the capability runs automatically;
  "Run capability" alone does nothing when the case has no evidence —
  the runs table then honestly stays empty until an artifact exists.
