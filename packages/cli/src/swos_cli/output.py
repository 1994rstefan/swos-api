"""Central rendering for human-readable and machine-readable CLI output."""

from __future__ import annotations

import json
import sys
from enum import StrEnum
from typing import Any
from unicodedata import category

from rich.console import Console


class OutputFormat(StrEnum):
    """Supported CLI output formats."""

    HUMAN = "human"
    JSON = "json"
    JSON_PRETTY = "json-pretty"


class OutputRenderer:
    """Render one structured result without leaking formatting into commands."""

    def __init__(self, output_format: OutputFormat) -> None:
        self.output_format = output_format

    def success(self, data: dict[str, Any], *, human: str) -> None:
        """Render a successful command result."""

        payload = {"ok": True, "data": data}
        if self.output_format is OutputFormat.HUMAN:
            Console(file=sys.stdout, highlight=False).print(_terminal_safe(human), markup=False)
            return
        self._write_json(payload)

    def error(self, code: str, message: str) -> None:
        """Render a failed command result."""

        if self.output_format is OutputFormat.HUMAN:
            Console(file=sys.stderr, highlight=False, style="bold red").print(
                _terminal_safe(message),
                markup=False,
            )
            return
        self._write_json({"ok": False, "error": {"code": code, "message": message}})

    def _write_json(self, payload: dict[str, Any]) -> None:
        if self.output_format is OutputFormat.JSON:
            rendered = json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
        else:
            rendered = json.dumps(payload, ensure_ascii=False, indent=2)
        sys.stdout.write(rendered + "\n")


def _terminal_safe(value: str) -> str:
    """Remove terminal-active controls while preserving intentional line breaks."""

    return "".join(
        character if character == "\n" or not category(character).startswith("C") else "\ufffd"
        for character in value
    )
