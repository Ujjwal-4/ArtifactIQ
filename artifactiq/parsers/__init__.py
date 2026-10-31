"""Parser registry: media type -> available BaseParser instances."""
from __future__ import annotations

from .base import BaseParser, ParseOutcome, ParserError, PARSER_VERSION  # noqa: F401
from .evtx import EvtxParser, EVENT_ID_MAP, EVTX_AVAILABLE
from .browser_sqlite import BrowserSqliteParser
from .csv_events import CsvEventsParser
from .json_events import JsonEventsParser
from .usb_setupapi import UsbSetupApiParser
from .registry import RegistryTextParser, RegistryHiveParser
from .usb_reg import UsbRegParser

EVTX_FALLBACK_NAME = "evtx"


def all_parsers() -> list[BaseParser]:
    return [
        EvtxParser(),
        BrowserSqliteParser(),
        CsvEventsParser(),
        JsonEventsParser(),
        UsbSetupApiParser(),
        RegistryTextParser(),
        RegistryHiveParser(),
        UsbRegParser(),
    ]


def parsers_for_media(media_type: str):
    return [p for p in all_parsers() if media_type in p.media_types]


def parser_by_name(name: str):
    for p in all_parsers():
        if p.name == name:
            return p
    return None
