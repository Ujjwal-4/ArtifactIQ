# Limitations — what ArtifactIQ does NOT do (read before relying on it)

## Evidence and integrity
- Hashes prove the **preserved copy** inside the evidence store is unchanged.
  They prove nothing about artifacts on the source system before/during/after
  collection.
- The evidence **Preview** is a read-only convenience over the preserved copy:
  a decoded first-4 KB snippet for text formats, table names + row counts for
  SQLite, a hexdump for binaries. Text truncation can cut the last snippet
  line mid-way; the authoritative content of record stays the Parse output
  (events) and the preserved bytes themselves. Hash re-verification inside the
  preview is skipped above 64 MB (disclosed in the modal), not silently.
- The custody ledger is hash-chained but stored in the same SQLite file as the
  analysis data. It is **tamper-evident, not tamper-proof**; an attacker with
  write access to the store can rewrite chain + data together. Export reports
  and custody JSON if you need an externally-held copy.
- Evidence copies are parked to a `trash` folder on removal, not shredded.

## Analysis
- Findings and ATT&CK mappings come from a small, versioned local rule set
  (`attack-rules/2025a…`). Absence of a finding means "rule did not fire",
  never "nothing happened".
- ATT&CK technique coverage is limited to the pinned rule table; there is no
  confidence-scored enterprise-wide mapping.
- Branches (B1–B7) are prioritized **questions** to investigate, not
  predictions of attacker behavior; the word "predictive" refers to pointing
  investigators at likely-productive next steps.
- Scenario Simulator chains (`sim-rules/2026a/1.0`, SIM-C1–C5) describe
  **typical attacker behavior**, not a model of this attacker. "Predicted"
  nodes are collection contracts (what artifact would prove/disprove the
  step), never claims that the step occurred. The knowledge base is a curated
  subset — many real attacker paths are not modeled, and any step executed
  inside a cleared-log window may be invisible REGARDLESS of the chain.
- Prevention text on simulation nodes cites ATT&CK mitigation M-codes but is
  generic good practice; it is not tailored to the case's actual exposure.
- Risk score is a deterministic policy formula over stored case inputs. It is
  a communication aid, not a probability of compromise.
- Timeline precision inherits artifact precision; events without a UTC-
  declaring timestamp are never guessed to a timezone.

## Platform
- **Disk-image analysis (p06) is real but scoped.** With `pytsk3` installed the
  app reads raw/`.dd`/`.img` images via The Sleuth Kit: MBR/GPT partition tables
  plus every filesystem TSK can open (NTFS, FAT12/16/32, exFAT, ext2–4, …).
  It *lists* files, directories, deleted entries and MACB timestamps; it does
  **not** carve files, mount volumes, or unzip containers. E01/VHD support
  depends on the TSK libs bundled in the wheel — unsupported formats fail the
  run with the engine's error text. Entry caps (25 000/image, depth 14) are
  reported as honest `truncated` notes. Without the engine the phase stays
  `blocked` with the install hint — it never fakes progress.
- No clustering beyond simple time buckets; no advanced entity resolution.
- Parser support is Windows-artifact oriented (evtx, registry, setupapi,
  Chrome/Chromium-style SQLite) plus generic JSON/CSV imports.
- No multi-user authentication model: it is a single-investigator,
  loopback-bound tool. Exposing it to a network is unsupported.
- LLM assist is optional and off unless configured; it only ever receives
  derived narrative text, and its output is clearly labeled assistive, not
  evidence.

## Live acquisition
- Requires `ARTIFACTIQ_ALLOW_LIVE=1`, is targeted and audited, and writes a
  **session file** on the endpoint: it is not and does not claim to be
  "zero-footprint".
- Denied access is reported, not retried silently; sources it cannot read are
  marked `denied`/`failed` in the session.

## Test budget caveats
- Parser rows capped by `ARTIFACTIQ_MAX_EVENTS` and a wall-clock timeout —
  very large artifacts are partially parsed with a recorded truncation
  warning, and coverage is computed accordingly.
