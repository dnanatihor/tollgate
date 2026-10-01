"""Response cache keyed by model, prompt version, lens, and unit content."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path


def cache_key(model_id: str, prompt_version: str, lens: str, unit_content: str) -> str:
    unit_hash = hashlib.sha256(unit_content.encode()).hexdigest()
    material = f"{model_id}|{prompt_version}|{lens}|{unit_hash}"
    return hashlib.sha256(material.encode()).hexdigest()


class ResponseCache:
    def __init__(self, directory: Path) -> None:
        self.directory = directory

    def get(self, key: str) -> str | None:
        path = self.directory / f"{key}.json"
        if not path.is_file():
            return None
        loaded = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(loaded, dict) or not isinstance(loaded.get("body"), str):
            return None
        body = loaded["body"]
        if not isinstance(body, str):
            return None
        return body

    def put(self, key: str, body: str) -> None:
        self.directory.mkdir(parents=True, exist_ok=True)
        path = self.directory / f"{key}.json"
        path.write_text(json.dumps({"body": body}), encoding="utf-8")
