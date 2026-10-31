# The 12 phases — status rules and honesty policy

Phase status values: `not_started`, `ready`, `in_progress`, `completed`,
`completed_with_warnings`, `blocked`, `unsupported`.

| Phase | Name | How status is derived | Honest notes |
|---|---|---|---|
| p01 | Cases | completed when the case exists with validated metadata | — |
| p02 | Acquisition plan | `ready` until a plan exists; `completed` when an acquisition session is planned with BOTH acknowledgments recorded (live acquisition planned or demo/import plan) | planned-only sessions are kept and shown as such — they are never auto-marked "run" |
| p03 | Acquisition / import | completed when ≥1 evidence item registered; `blocked` if none | upload-only by default; live collection is opt-in |
| p04 | Parsing | completed when ≥1 parser run is `completed`; `completed_with_warnings` when warnings exist; `failed` runs are not hidden | corrupt input ⇒ run marked `failed` with reason; disk-image media is *delegated* to p06, never counted as an "unsupported" parser failure |
| p05 | Integrity & custody | `completed` when every evidence item passed intake verification (`verified`/`recorded`/`retained`); `completed_with_warnings` if any `mismatch`/`error`; `not_started` without evidence | hash matches the *preserved copy*, not the world; re-verify any item at any time |
| p06 | Disk-image analysis | `blocked` with no disk image in scope (optional phase); `ready` when an image is registered but not analyzed; `completed` after a real engine run | powered by **pytsk3 / The Sleuth Kit**: reads MBR/GPT partition tables, walks the filesystems it can open (NTFS, FAT12/16/32, exFAT, ext2–4 …), lists files/dirs incl. deleted entries with MACB times; read-only — the preserved copy is SHA-256 checked before and after each run; unsupported filesystems/partitions become `completed_with_warnings` with the engine error; **no engine installed ⇒ blocked with the install hint**, never faked |
| p07 | Unified timeline | completed where structured events exist; GENUINE timestamp problems (a source timestamp dropped/unparsed) ⇒ `completed_with_warnings` | events whose source format carries no timestamp at all (e.g. text .reg exports) are shown on the timeline as "(no timestamp in source)" with no warning — a format limitation is not a failure and no timestamp is ever invented |
| p08 | Graph + ATT&CK | completed when mappings/graph rebuilt; zero mappings is a *honest zero*, not an error | mapping table is local, ATT&CK v15 |
| p09 | Branches | completed when branches generated | branches are questions with formulas, never conclusions. The **Scenario Simulator** tab extends this phase: clicking a detected trigger walks a versioned behavioral chain (`sim-rules/2026a/1.0`) — each node is `observed` (cites this case's events) or `predicted` (knowledge-base expectation to search for, never an assertion). Simulation does NOT change phase status and adds no phase — the 12-phase contract is unchanged |
| p10 | Risk | completed when a score is stored | formula and inputs always visible |
| p11 | Explanation | `completed` once the explanation was actually built and shown (assembled on demand, one record per pending change) | without an LLM the local grounded narrative is used |
| p12 | Reports | completed once a report row exists; `ready` before | all five kinds verified in tests |

Statuses are persisted in `phase_runs` (latest per phase per case) and shown
on the Overview tab with Refresh Phases.

## Reaching the full 12/12 (honestly)

Every phase gate is a real artifact — the counter never counts invented work:

1. **p06 (disk image)** — install the engine into the project venv
   (`.venv\Scripts\python -m pip install pytsk3`; a prebuilt wheel ships for
   CPython 3.13 on Windows), register a disk image on the Evidence tab
   (`.raw .dd .img .e01 .vhd .vhdx .001`, media type `disk_image`), then press
   **Analyze disk image(s) now**. Without a disk image in scope the phase stays
   `blocked` *by design* (it is "when applicable").
2. **p02** — create an acquisition plan/session (Acquisition tab) with both
   acknowledgments checked. A planned-only session is already an honest completion.
3. **p05** — every evidence item verified (`verified`/`recorded` at intake).
   A `mismatch` demotes the phase to `completed_with_warnings` — on purpose.
4. **p11** — open the Explanation/summary view once (the narrative is built and
   recorded on demand).
5. **p12** — generate at least one report (Reports tab).

The synthetic demo case (`Load demo`) runs all of these real steps itself, so a
successfully loaded demo lands at **12/12** (with honest warnings where events
have unparsed timestamps).

## Disk-image engine caveats (honest limits)

- E01/`$OrphanFiles`-style carving depends on which TSK libraries the wheel
  bundles; unsupported containers fail the run with the engine's error text.
- Entry caps: 25 000 entries/image, 14 directory depth — beyond that the run
  reports `completed_with_warnings` with a truncation note (never silent).
- DOS/FAT timestamps carry no timezone; TSK interprets them in the local
  timezone of the machine doing the analysis. This is a genuine property of the
  format, reported in the run's times.
