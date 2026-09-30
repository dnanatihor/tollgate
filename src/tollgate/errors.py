"""Errors that the CLI maps to process exit codes."""

from __future__ import annotations


class ConfigError(Exception):
    """Invalid configuration. The CLI exits 2 and names ``key``."""

    def __init__(self, key: str, message: str) -> None:
        self.key = key
        self.message = message
        super().__init__(f"{key}: {message}")

    def format_cli(self) -> str:
        return f"configuration error: {self.key}: {self.message}"
