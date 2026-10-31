"""Timeline service: server-side filtering, pagination, clustering, export."""
from __future__ import annotations

import csv as _csv
import io
import json
from datetime import datetime, timezone, timedelta

from ..db import query, one, jload
from ..util.ids import now_iso


SORTABLE = {"ts_utc", "event_type", "category", "username", "hostname"}


def search(case_id: str, args: dict, page: int = 1, per_page: int = 100) -> dict:
    per_page = max(10, min(int(per_page or 100), 500))
    page = max(1, int(page or 1))
    where = ["case_id=?"]
    params: list = [case_id]
    if q := (args.get("q") or "").strip():
        like = f"%{q}%"
        q_cols = (
            "event_type", "username", "process_name", "command_line", "hostname",
            "channel", "provider", "source_path", "destination_path",
            "raw_ref", "event_code",
        )
        where.append("(" + " OR ".join(f"{col} LIKE ?" for col in q_cols) + ")")
        params += [like] * len(q_cols)
    if v := (args.get("event_type") or "").strip():
        where.append("event_type=?")
        params.append(v)
    if v := (args.get("category") or "").strip():
        where.append("category=?")
        params.append(v)
    if v := (args.get("evidence_id") or "").strip():
        where.append("evidence_id=?")
        params.append(v)
    if v := (args.get("user") or "").strip():
        where.append("(username=? OR user_sid=?)")
        params += [v, v]
    if v := (args.get("host") or "").strip():
        where.append("hostname=?")
        params.append(v)
    if v := (args.get("from") or "").strip():
        where.append("ts_utc >= ?")
        params.append(v)
    if v := (args.get("to") or "").strip():
        where.append("ts_utc <= ?")
        params.append(v)
    wsql = " AND ".join(where)
    total = one(f"SELECT COUNT(*) AS n FROM events WHERE {wsql}", params)["n"]
    sort = args.get("sort") if args.get("sort") in SORTABLE else "ts_utc"
    direction = "DESC" if (args.get("dir") or "asc").lower() == "desc" else "ASC"
    if sort == "ts_utc":
        order = f"ts_utc IS NULL, ts_utc {direction}"
    else:
        order = f"{sort} {direction}, ts_utc ASC"
    rows = query(
        f"SELECT * FROM events WHERE {wsql} ORDER BY {order} LIMIT ? OFFSET ?",
        (*params, per_page, (page - 1) * per_page),
    )
    facets = {
        "event_types": query(
            "SELECT event_type, COUNT(*) AS n FROM events WHERE case_id=? GROUP BY event_type ORDER BY n DESC",
            (case_id,)),
        "categories": query(
            "SELECT category, COUNT(*) AS n FROM events WHERE case_id=? GROUP BY category ORDER BY n DESC",
            (case_id,)),
        "users": query(
            "SELECT username, COUNT(*) AS n FROM events WHERE case_id=? AND username IS NOT NULL GROUP BY username ORDER BY n DESC LIMIT 25",
            (case_id,)),
        "hosts": query(
            "SELECT hostname, COUNT(*) AS n FROM events WHERE case_id=? AND hostname IS NOT NULL GROUP BY hostname ORDER BY n DESC",
            (case_id,)),
    }
    unknown_ts = one(
        "SELECT COUNT(*) AS n FROM events WHERE case_id=? AND ts_utc IS NULL", (case_id,))["n"]
    no_src = one(
        "SELECT COUNT(*) AS n FROM events WHERE case_id=? "
        "AND ts_utc IS NULL AND ts_source='no_timestamp'", (case_id,))["n"]
    return {
        "total": total,
        "page": page,
        "per_page": per_page,
        "items": [dict(r) for r in rows],
        "facets": {k: [dict(r) for r in v] for k, v in facets.items()},
        "unknown_ts_count": unknown_ts,
        "no_ts_in_source_count": no_src,
    }


def cluster(case_id: str, gap_minutes: int = 30, limit: int = 60) -> list:
    """Simple gap-based clustering for navigation (not an analytical claim)."""
    clusters = []
    prev_end = None
    cluster = None
    detailed = query(
        "SELECT ts_utc, event_type FROM events WHERE case_id=? AND ts_utc IS NOT NULL "
        "ORDER BY ts_utc", (case_id,))
    gap = timedelta(minutes=gap_minutes)
    for r in detailed:
        try:
            ts = datetime.fromisoformat(r["ts_utc"].replace("Z", "+00:00"))
        except (ValueError, AttributeError):
            continue
        if cluster and ts - prev_end <= gap:
            cluster["count"] += 1
            cluster["end"] = r["ts_utc"]
            cluster["types"].add(r["event_type"])
        else:
            if cluster:
                clusters.append(_finalize(cluster))
            cluster = {"start": r["ts_utc"], "end": r["ts_utc"], "count": 1, "types": {r["event_type"]}}
        prev_end = ts
    if cluster:
        clusters.append(_finalize(cluster))
    # big-first ordering for display, capped
    clusters.sort(key=lambda c: c["count"], reverse=True)
    return clusters[:limit]


def _finalize(c) -> dict:
    return {
        "start": c["start"], "end": c["end"], "count": c["count"],
        "types": sorted(c["types"]),
    }


def export_csv(case_id: str, args: dict | None = None) -> str:
    args = args or {}
    data = search(case_id, args, page=1, per_page=500)
    buf = io.StringIO()
    w = _csv.writer(buf, quoting=_csv.QUOTE_MINIMAL)
    cols = ["id", "ts_utc", "ts_precision", "ts_original", "event_type", "category",
            "event_code", "record_id", "channel", "provider", "hostname", "username",
            "user_sid", "process_name", "process_id", "command_line", "source_ip",
            "destination_ip", "source_path", "destination_path", "raw_ref",
            "evidence_id", "parser", "parse_status", "tags"]
    w.writerow(["# ArtifactIQ timeline export", now_iso(), "UTC timestamps; missing timestamps remain empty"])
    w.writerow(cols)
    for e in data["items"]:
        tags = ",".join(jload(e.get("tags"), []))
        w.writerow([e.get(c) or "" for c in cols[:-1]] + [tags])
    return buf.getvalue()


def stats(case_id: str) -> dict:
    total = one("SELECT COUNT(*) AS n FROM events WHERE case_id=?", (case_id,))["n"]
    unknown = one("SELECT COUNT(*) AS n FROM events WHERE case_id=? AND ts_utc IS NULL", (case_id,))["n"]
    per_day = query(
        "SELECT substr(ts_utc,1,10) AS day, COUNT(*) AS n FROM events "
        "WHERE case_id=? AND ts_utc IS NOT NULL GROUP BY day ORDER BY day",
        (case_id,))
    per_type = query(
        "SELECT event_type, COUNT(*) AS n FROM events WHERE case_id=? "
        "GROUP BY event_type ORDER BY n DESC LIMIT 20", (case_id,))
    top_users = query(
        "SELECT username, COUNT(*) AS n FROM events WHERE case_id=? AND username IS NOT NULL "
        "GROUP BY username ORDER BY n DESC LIMIT 10", (case_id,))
    return {"total": total, "unknown_ts": unknown, "per_day": [dict(r) for r in per_day],
            "per_type": [dict(r) for r in per_type], "top_users": [dict(r) for r in top_users]}
