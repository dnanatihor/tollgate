"""Structured model output with a JSON fallback and one repair call."""

from __future__ import annotations

import json
from typing import Protocol

from pydantic import BaseModel, ValidationError

_SCHEMA_INSTRUCTION = "\n\nReturn only a JSON object matching this JSON Schema, with no markdown:\n"


class UnsupportedStructured(Exception):
    """The model cannot use native structured output."""


class ReviewFailed(Exception):
    """The unit could not be reviewed after the repair call."""


class ChatBackend(Protocol):
    model_id: str
    supports_native: bool

    async def complete(self, system: str, user: str) -> str: ...

    async def complete_structured(
        self,
        system: str,
        user: str,
        schema: type[BaseModel],
    ) -> BaseModel: ...


async def structured_output(
    model: ChatBackend,
    *,
    system: str,
    user: str,
    schema: type[BaseModel],
    mode: str,
) -> BaseModel:
    """Try native structured output, then a JSON prompt with one repair."""
    if mode in {"auto", "native"} and model.supports_native:
        try:
            return await model.complete_structured(system, user, schema)
        except UnsupportedStructured:
            if mode == "native":
                raise
    prompt = user + _SCHEMA_INSTRUCTION + json.dumps(schema.model_json_schema())
    raw = await model.complete(system, prompt)
    try:
        return _validate_json(raw, schema)
    except (ValidationError, ValueError) as exc:
        repair = (
            prompt
            + "\n\nThe previous reply failed validation:\n"
            + str(exc)
            + "\nReturn only a JSON object."
        )
        repaired = await model.complete(system, repair)
        try:
            return _validate_json(repaired, schema)
        except (ValidationError, ValueError) as repair_error:
            raise ReviewFailed(str(repair_error)) from repair_error


def extract_json_object(text: str) -> str:
    """Return the first balanced JSON object in ``text``."""
    start = text.find("{")
    if start < 0:
        raise ValueError("no JSON object in the reply")
    depth = 0
    in_string = False
    escape = False
    for index in range(start, len(text)):
        char = text[index]
        if in_string:
            if escape:
                escape = False
            elif char == "\\":
                escape = True
            elif char == '"':
                in_string = False
            continue
        if char == '"':
            in_string = True
        elif char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return text[start : index + 1]
    raise ValueError("unterminated JSON object")


def _validate_json(text: str, schema: type[BaseModel]) -> BaseModel:
    payload = json.loads(extract_json_object(text))
    return schema.model_validate(payload)


def looks_like_json_prompt(user: str) -> bool:
    return "Return only a JSON object" in user and "JSON Schema" in user
