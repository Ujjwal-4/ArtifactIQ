"""Entity/relationship extraction from normalized events, with provenance.

Every node/relationship carries the evidence ids that produced it so the UI
can always trace a relationship back to evidence.
"""
from __future__ import annotations

from ..db import query, insert, execute, jdump, jload
from ..util.ids import new_id, truncate

ENTITY_TYPES = ("user", "host", "process", "file", "network", "usb", "service", "task")


def _key(etype: str, name: str) -> str:
    return f"{etype}::{(name or 'unknown').strip().lower()}"[:240]


def build_graph(case_id: str) -> dict:
    """Rebuild the graph from normalized events (idempotent per case)."""
    execute("DELETE FROM relationships WHERE case_id=?", (case_id,))
    execute("DELETE FROM entities WHERE case_id=?", (case_id,))
    events = query(
        "SELECT * FROM events WHERE case_id=? AND ts_utc IS NOT NULL ORDER BY ts_utc",
        (case_id,))
    nodes: dict[str, dict] = {}
    edges: dict[str, dict] = {}

    def node(etype, name, attrs=None):
        name = str(name or "").strip()
        if not name:
            return None
        k = _key(etype, name)
        n = nodes.get(k)
        if not n:
            n = {"id": new_id("en"), "etype": etype, "name": truncate(name, 120), "attrs": {}}
            nodes[k] = n
        if attrs:
            n["attrs"].update(attrs)
        return n["id"]

    def edge(src, dst, kind, evidence_id, ts):
        if not src or not dst or src == dst:
            return
        k = f"{src}->{kind}->{dst}"
        e = edges.get(k)
        if not e:
            e = {"src": src, "dst": dst, "kind": kind, "evs": set(), "n": 0, "last": ""}
            edges[k] = e
        e["evs"].add(evidence_id)
        e["n"] += 1
        if ts:
            e["last"] = max(e["last"], ts)

    for ev in events:
        eid, ts = ev["id"], ev["ts_utc"]
        ev_id = ev["evidence_id"]
        fallback = (not ev["username"]) and ev["user_sid"]
        user_id = node("user", ev["username"] or ("sid:" + ev["user_sid"] if fallback else ""))
        host_id = node("host", ev["hostname"] or "unknown-host")
        proc_name = ev["process_name"] or (ev["command_line"].split("\x01")[0].split()[-1] if False else None)
        proc_id = None
        if ev["process_name"]:
            attrs = {"last_pid": ev["process_id"]} if ev["process_id"] else None
            proc_id = node("process", ev["process_name"], attrs)
        if user_id and host_id:
            edge(user_id, host_id, "authenticated_on", ev_id, ts)
        if proc_id and user_id:
            edge(user_id, proc_id, "ran_process", ev_id, ts)
        if proc_id and host_id:
            edge(proc_id, host_id, "executed_on", ev_id, ts)
        if ev["command_line"] and proc_id:
            # keep the command visible as attribute, not as a fake node
            nodes[_key("process", ev["process_name"])]["attrs"].setdefault("command_lines", set())
        for path_field in ("source_path", "destination_path"):
            val = ev[path_field]
            if not val:
                continue
            et = _classify_path(val)
            nid = node(et, val)
            if nid:
                kind = {
                    ("destination_path", "usb"): "connected_usb",
                    ("source_path", "usb"): "connected_usb",
                    ("destination_path", "task"): "scheduled_task",
                    ("destination_path", "service"): "installed_service",
                    ("source_path", "service"): "installed_service",
                }.get((path_field, et), ("referenced" if path_field == "source_path" else "wrote_to"))
                for src in filter(None, (proc_id, user_id, host_id)):
                    break
                src_node = proc_id or user_id or host_id
                edge(src_node, nid, kind, ev_id, ts)
        if ev["destination_ip"]:
            nip = node("network", ev["destination_ip"])
            edge(proc_id or user_id or host_id, nip, "network_connection", ev_id, ts)
        if ev["source_ip"] and ev["source_ip"] not in ("-", "0.0.0.0", "::1"):
            sip = node("network", ev["source_ip"])
            edge(sip, host_id, "connection_from", ev_id, ts)
        if ev["category"] == "usb" and ev["event_code"]:
            uid = node("usb", ev["event_code"])
            edge(uid, host_id, "connected_to", ev_id, ts)

    for n in nodes.values():
        n["attrs"] = {k: len(v) if isinstance(v, set) else v for k, v in n["attrs"].items()}
        insert("entities", {
            "id": n["id"], "case_id": case_id, "etype": n["etype"], "name": n["name"],
            "attrs": jdump(n["attrs"]), "key": _key(n["etype"], n["name"]),
        })
    for e in edges.values():
        insert("relationships", {
            "id": new_id("rl"), "case_id": case_id, "src_id": e["src"], "dst_id": e["dst"],
            "kind": e["kind"], "evidence_ids": jdump(sorted(e["evs"])),
            "count": e["n"], "last_ts": e["last"] or None,
        })
    return {"nodes": len(nodes), "edges": len(edges)}


def _classify_path(val: str) -> str:
    v = (val or "").lower().replace("%26", "&")
    if "usbstor" in v or "vid_" in v or "mountedvolume" in v or v.startswith("usb"):
        return "usb"
    if v.startswith("\\\\") or v.startswith("//"):
        return "network"
    if "\\tasks\\" in v or v.startswith("schtasks") or "microsoft\\windows\\microsoft" in v:
        return "task"
    if "\\services\\" in v or "memory_backup?imagepath" in v or "system_currentcontrolset_services" in v:
        return "service"
    return "file"


def get_graph(case_id: str, focus: str | None = None, hops: int = 1,
              limit_nodes: int = 250) -> dict:
    ents = {r["id"]: dict(r) for r in query("SELECT * FROM entities WHERE case_id=?", (case_id,))}
    rels = [dict(r) for r in query("SELECT * FROM relationships WHERE case_id=?", (case_id,))]
    if focus:
        key = focus if "::" in focus else None
        targets = {eid for eid, n in ents.items() if (key and n["key"] == key) or (not key and n["name"] == focus)}
        if not targets:
            targets = {eid for eid, n in ents.items() if focus.lower() in n["name"].lower()}
        if not targets:
            return {"nodes": [], "relationships": [], "note": "focus entity not found in graph"}
        frontier: set = set(targets)
        for _ in range(max(1, hops)):
            nxt = set()
            for r in rels:
                if r["src_id"] in frontier:
                    nxt.add(r["dst_id"])
                if r["dst_id"] in frontier:
                    nxt.add(r["src_id"])
            frontier |= nxt
        keep = frontier
    else:
        deg: dict = {}
        for r in rels:
            deg[r["src_id"]] = deg.get(r["src_id"], 0) + r["count"]
            deg[r["dst_id"]] = deg.get(r["dst_id"], 0) + r["count"]
        ranked = sorted(deg.items(), key=lambda kv: kv[1], reverse=True)[:limit_nodes]
        keep = {k for k, _ in ranked}
    nodes_out = [{
        "id": eid, "type": n["etype"], "name": n["name"],
        "attrs": jload(n["attrs"], {}),
    } for eid, n in ents.items() if eid in keep]
    rels_out = [{
        "id": r["id"], "source": r["src_id"], "target": r["dst_id"],
        "kind": r["kind"], "count": r["count"],
        "evidence_ids": jload(r["evidence_ids"]), "last_ts": r["last_ts"],
    } for r in rels if r["src_id"] in keep and r["dst_id"] in keep]
    return {"nodes": nodes_out, "relationships": rels_out}
