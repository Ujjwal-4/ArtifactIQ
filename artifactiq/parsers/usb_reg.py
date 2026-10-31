"""Specialized USB artifact check from .reg text (USBSTOR / MountPoints2)."""
from __future__ import annotations

from .base import BaseParser, ParseOutcome, ParserError
from ..util.ids import truncate

import re

_USBSTOR = re.compile(r"USBSTOR[^\r\n]*", re.IGNORECASE)
_KP = re.compile(r"^\[(?P<key>[^\]]+)\]")


class UsbRegParser(BaseParser):
    name = "usb_reg"
    media_types = ("registry_export",)
    needs = ("stdlib re",)

    def parse(self, path, evidence_row, limit: int) -> ParseOutcome:
        from .registry import RegistryTextParser

        out = RegistryTextParser().parse(path, evidence_row, limit)
        focused = []
        for ev in out.events:
            kp = (ev.get("source_path") or "")
            if "usbstor" in kp.lower() or "mountpoints2" in kp.lower():
                ev["channel"] = "usb_registry_focus"
                focused.append(ev)
        if focused:
            out.events = focused
        elif not out.events:
            out.warnings.append("No USBSTOR or MountPoints2 entries were present in this .reg export.")
        return out
