"""A deterministic chat backend for tests. It never calls a network model."""

from __future__ import annotations

from pydantic import BaseModel

from tollgate.llm.structured import UnsupportedStructured, extract_json_object


class ScriptedChat:
    """Replies in order. Native mode parses the next reply as the schema."""

    def __init__(
        self,
        replies: list[str],
        *,
        model_id: str = "scripted:test",
        supports_native: bool = True,
    ) -> None:
        self.model_id = model_id
        self.supports_native = supports_native
        self._replies = list(replies)
        self.completions: list[tuple[str, str]] = []
        self.structured_calls: list[str] = []

    async def complete(self, system: str, user: str) -> str:
        self.completions.append((system, user))
        return self._pop()

    async def complete_structured(
        self,
        system: str,
        user: str,
        schema: type[BaseModel],
    ) -> BaseModel:
        if not self.supports_native:
            raise UnsupportedStructured(self.model_id)
        self.structured_calls.append(user)
        raw = self._pop()
        return schema.model_validate_json(extract_json_object(raw))

    def _pop(self) -> str:
        if not self._replies:
            raise RuntimeError("scripted model has no replies left")
        return self._replies.pop(0)
