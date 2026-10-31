"""Path safety for untrusted upload names and stored evidence paths.

Treat evidence as untrusted: paths returned here are always relative to a
controlled root, and are verified by resolve_within.
"""
from __future__ import annotations

import os
import re
import secrets
from pathlib import Path, PurePosixPath, PureWindowsPath

_UNSAFE = re.compile(r'[<>:"|?*\x00-\x1f]')


def safe_original_name(name: str, fallback: str = "unnamed") -> str:
    """Human-readable display name, hardened but not used as a storage path."""
    name = (name or "").strip()
    # remove path separators entirely (windows + posix)
    name = name.replace("\\", "/").split("/")[-1]
    name = _UNSAFE.sub("_", name)
    name = name.strip(" .") or fallback
    return name[:180]


def storage_name(extension: str) -> str:
    """Randomized internal storage name. The client path is never used."""
    ext = extension.lstrip(".").replace(" ", "_")[:16]
    ext = _UNSAFE.sub("", ext)
    return f"{secrets.token_hex(10)}{('.' + ext) if ext else ''}"


def resolve_within(root: str | Path, relative: str) -> Path:
    """Resolve a stored relative path and assert containment.

    Raises ValueError on any escape attempt (traversal, absolute path, UNC).
    """
    root_p = Path(root)
    rel = PurePosixPath((relative or "").replace("\\", "/"))
    if rel.is_absolute():
        raise ValueError("Absolute path supplied where a relative path was expected.")
    candidate = (root_p / rel).resolve()
    root_resolved = root_p.resolve()
    if not candidate.is_relative_to(root_resolved):
        raise ValueError("Resolved path escapes the controlled storage root.")
    return candidate


def evidence_store_subpath(stored_name: str, case_id_hint: str = "") -> str:
    """Subdirectory layout: store/AB/<stored_name>/ under evidence dir."""
    prefix = (case_id_hint or stored_name)[:2].replace("_", "a")
    prefix = re.sub(r"[^a-zA-Z0-9]", "a", prefix)[:2] or "aa"
    return f"{prefix}/{stored_name}"
