"""SHA-256 hashing, streaming, and verification."""
from __future__ import annotations

import hashlib
import os
from pathlib import Path

BLOCK = 1024 * 1024


def sha256_file(path: str | Path, size_limit: int = 0) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        while True:
            chunk = fh.read(BLOCK)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def sha256_text(data: str) -> str:
    return hashlib.sha256(data.encode("utf-8", "surrogatepass")).hexdigest()


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def file_size(path: str | Path) -> int:
    return os.path.getsize(path)


def quick_fingerprint(path: str | Path) -> dict:
    """Cheap guard against re-registering the same bytes twice in a case.

    This is a convenience check only - it does NOT prove identity of the
    original source (Section 3.1 / 3.2 of the methodology).
    """
    st = os.stat(path)
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        # hash first and last 64 KiB + size (cheap, deterministic, documented)
        head = fh.read(65536)
        if st.st_size > 131072:
            fh.seek(-65536, os.SEEK_END)
            tail = fh.read(65536)
        else:
            tail = b""
        digest.update(str(st.st_size).encode())
        digest.update(head)
        digest.update(tail)
    return {"size": st.st_size, "fingerprint": digest.hexdigest()}
