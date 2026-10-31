"""Chrome/Chromium History SQLite parser (read-only, safe copy semantics)."""
from __future__ import annotations

import sqlite3
import tempfile
from pathlib import Path

from .base import BaseParser, ParseOutcome, ParserError
from ..util import timestamps as tsu
from ..util.ids import truncate

GOOGLE_EPOCH_US = 11644473600000000  # Chrome epoch offset

DDL_HINTS = {
    "urls": ("visit_count", "hidden"),
    "visits": ("url", "visit_time", "transition", "from_visit"),
    "downloads": ("target_path", "start_time", "tab_url"),
}


class BrowserSqliteParser(BaseParser):
    name = "browser_sqlite"
    media_types = ("browser_sqlite", "generic_sqlite")
    needs = ("stdlib sqlite3",)

    def parse(self, path, evidence_row, limit: int) -> ParseOutcome:
        out = ParseOutcome()
        # Open strictly read-only on a throwaway copy so the original working
        # copy can never be modified (journal files included).
        tmp = tempfile.mkdtemp(prefix="aiq_browser_")
        try:
            work = Path(tmp) / "work.sqlite"
            work.write_bytes(Path(str(path)).read_bytes())
            conn = sqlite3.connect(f"file:{work}?mode=ro", uri=True)
            try:
                tables = {r[0] for r in conn.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'")}
                if "urls" not in tables or "visits" not in tables:
                    # Unsupported schema is honest: not a browser DB we know.
                    out.errors.append({
                        "raw_ref": "schema",
                        "message": "SQLite file does not contain Chrome 'urls'/'visits' tables; not parsed as browser history.",
                    })
                    conn.close()
                    return out
                if "downloads" in tables:
                    out.events.extend(self._downloads(conn, limit, out))
                out.events.extend(self._visits(conn, out))
                return out
            finally:
                conn.close()
        except sqlite3.DatabaseError as exc:
            raise ParserError(f"Cannot open SQLite database (corrupt or not SQLite?): {exc}") from exc
        finally:
            for f in Path(tmp).glob("*"):
                try:
                    f.unlink()
                except OSError:
                    pass

    def _downloads(self, conn, limit, out: ParseOutcome) -> list:
        events = []
        base = {
            "event_type": "file_downloaded", "category": "browser",
            "channel": "browser_downloads", "provider": "SQLite", "parse_status": "ok",
            "parser": self.name, "parser_version": "v2",
        }
        try:
            rows = conn.execute(
                "SELECT id, target_path, tab_url, start_time, received_bytes, danger_type, "
                "opened FROM downloads ORDER BY start_time ASC"
            ).fetchall()
        except sqlite3.DatabaseError as exc:
            out.errors.append({"raw_ref": "downloads", "message": f"downloads query failed: {exc}"})
            return events
        for r in rows:
            if limit is not None and len(events) >= limit:
                out.skipped += 1
                continue
            # columns: (id, target_path, tab_url, start_time, received_bytes,
            #           danger_type, opened)
            raw_time = r[3] if len(r) > 3 else 0
            dt = tsu.dt_from_chrome_ms(raw_time)
            tags = ["browser_download"]
            if raw_time == 0:
                tags.append("no_timestamp")
            if (r[4] if len(r) > 4 else None) and int(r[4]) > 0:
                tags.append(f"received_bytes={r[4]}")
            if (r[5] if len(r) > 5 else None) == 1:
                tags.append("marked_as_dangerous")
            if (r[6] if len(r) > 6 else None) == 1:
                tags.append("opened")
            events.append({
                **base,
                "ts_utc": tsu.to_utc_iso(dt) if dt else None,
                "ts_original": str(raw_time),
                "ts_precision": "utc_microsecond" if dt else "unknown",
                "ts_source": "downloads.start_time (Chrome epoch instructions)",
                "event_code": "download",
                "record_id": str(r[0]),
                "destination_path": r[1],
                "source_path": truncate(r[2], 300),
                "raw_ref": f"downloads.id={r[0]}",
                "tags": tags,
                "confidence": 0.9,
            })
        return events

    def _visits(self, conn, out: ParseOutcome) -> list:
        events = []
        base = {
            "event_type": "url_visited", "category": "browser", "channel": "Chrome_History",
            "provider": "SQLite", "parse_status": "ok", "parser": self.name, "parser_version": "v2",
        }
        try:
            rows = conn.execute(
                "SELECT v.id, u.url, u.title, v.visit_time, v.transition "
                "FROM visits v JOIN urls u ON u.id = v.url ORDER BY v.visit_time ASC"
            ).fetchall()
        except sqlite3.DatabaseError as exc:
            out.errors.append({"raw_ref": "visits", "message": f"visits query failed: {exc}"})
            return events
        for r in rows:
            dt = tsu.dt_from_chrome_ms(r[3])
            transition = r[4] & 0xFF
            events.append({
                **base,
                "ts_utc": tsu.to_utc_iso(dt) if dt else None,
                "ts_original": str(r[3]),
                "ts_precision": "utc_microsecond" if dt else "unknown",
                "ts_source": "visits.visit_time",
                "event_code": f"visit_type={transition}",
                "record_id": str(r[0]),
                "source_path": truncate(r[1], 500),
                "destination_path": truncate(r[2], 300),
                "raw_ref": f"visits.id={r[0]}",
                "tags": ["browser_visit"],
                "confidence": 0.85,
            })
        return events
