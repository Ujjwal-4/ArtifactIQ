# ArtifactIQ — Predictive Digital Forensics Platform

Prototype v0.1: landing page and investigation-mode selector.

## Current scope
- Professional landing page for ArtifactIQ.
- Three investigation entry points:
  1. Run authorized forensic collection on the local system.
  2. Analyze a `.dd` / `.E01` disk image.
  3. Run a targeted forensic check (Event Logs, Registry, USB, Browser, File System, Login Activity).
- No system collection is executed yet. The buttons intentionally stop at the workflow entry point until the acquisition modules are implemented and tested.
- `/health` endpoint for a basic service check.

## Run

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python app.py
```

Open `http://127.0.0.1:5000`.

## Design direction
The interface takes inspiration from professional DFIR products that emphasize evidence sources, timelines, dashboards, and investigator-controlled workflows, while using a distinct visual language for ArtifactIQ. Magnet AXIOM emphasizes case dashboards, evidence sources, timelines, analytics and reporting; Velociraptor emphasizes targeted artifact collection and endpoint investigation. ArtifactIQ's planned UI combines these ideas with its own predictive-forensics workflow.

## Security note
Do not run future live-acquisition modules against systems you do not own or have explicit authorization to examine. For development, use a dedicated Windows test VM and known forensic test images.
