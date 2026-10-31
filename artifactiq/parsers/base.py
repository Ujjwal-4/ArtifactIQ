"""Parser registry and base types."""
from __future__ import annotations

from dataclasses import dataclass, field

PARSER_VERSION = "v2"

EVENT_FIELDS = [
    "ts_utc", "ts_original", "ts_precision", "ts_source",
    "event_type", "category", "channel", "provider", "event_code", "record_id",
    "hostname", "username", "user_sid",
    "process_name", "process_id", "parent_process_id", "command_line",
    "source_ip", "destination_ip", "source_path", "destination_path",
    "raw_ref", "parser", "parser_version", "parse_status", "confidence", "tags",
]

_DEFAULTS = {
    "channel": None, "provider": None, "event_code": None, "record_id": None,
    "hostname": None, "username": None, "user_sid": None,
    "process_name": None, "process_id": None, "parent_process_id": None, "command_line": None,
    "source_ip": None, "destination_ip": None, "source_path": None, "destination_path": None,
    "confidence": None,
}


class ParserError(Exception):
    """Raised for fatal per-file problems; service catches and records it."""


@dataclass
class ParseOutcome:
    events: list = field(default_factory=list)
    errors: list = field(default_factory=list)     # structured: [{"raw_ref":..,"message":..}]
    warnings: list = field(default_factory=list)
    skipped: int = 0

    @property
    def status(self) -> str:
        if self.errors and not self.events:
            return "failed"
        if self.errors:
            return "completed_with_errors"
        return "completed"


class BaseParser:
    name = "base"
    media_types: tuple = ()
    needs: tuple = ()

    def parse(self, path, evidence_row, limit: int) -> ParseOutcome:
        raise NotImplementedError

    def setup_defaults(self, ev_shader: str = "", channel: str | None = None):
        return dict(_DEFAULTS)
