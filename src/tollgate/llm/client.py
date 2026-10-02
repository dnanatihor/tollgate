"""LangChain chat client and the ``models check`` probe."""

from __future__ import annotations

import time
from typing import Literal

from pydantic import BaseModel

from tollgate.config import TollgateConfig
from tollgate.errors import ConfigError
from tollgate.llm.schemas import Probe
from tollgate.llm.structured import UnsupportedStructured, structured_output

RoleName = Literal["triage", "review", "critic"]
_LOCAL_PROVIDERS = {"ollama"}


class ModelUnreachable(Exception):
    """A configured model could not be called. The CLI exits 3."""


class LangChainChat:
    """``init_chat_model`` wrapper. Tests use ``ScriptedChat`` instead."""

    def __init__(self, model_id: str, *, base_url: str | None, temperature: float) -> None:
        from langchain.chat_models import init_chat_model

        provider, model = _split_model(model_id)
        self.model_id = model_id
        self.supports_native = True
        if base_url:
            self._model = init_chat_model(
                model,
                model_provider=provider,
                temperature=temperature,
                base_url=base_url,
            )
        else:
            self._model = init_chat_model(
                model,
                model_provider=provider,
                temperature=temperature,
            )

    async def complete(self, system: str, user: str) -> str:
        message = await self._model.ainvoke([("system", system), ("human", user)])
        content = message.content
        if isinstance(content, str):
            return content
        return str(content)

    async def complete_structured(
        self,
        system: str,
        user: str,
        schema: type[BaseModel],
    ) -> BaseModel:
        try:
            structured = self._model.with_structured_output(schema)
        except Exception as exc:
            raise UnsupportedStructured(str(exc)) from exc
        try:
            result = await structured.ainvoke([("system", system), ("human", user)])
        except Exception as exc:
            raise UnsupportedStructured(str(exc)) from exc
        if isinstance(result, schema):
            return result
        return schema.model_validate(result)


def enforce_local_only(config: TollgateConfig, model_id: str) -> None:
    if not config.llm.local_only:
        return
    provider, _model = _split_model(model_id)
    if provider in config.llm.allowed_providers or provider in _LOCAL_PROVIDERS:
        return
    base = config.llm.base_url or ""
    if base.startswith(("http://127.0.0.1", "http://localhost", "http://[::1]")):
        return
    raise ConfigError(
        "llm.local_only",
        f"{model_id} is not a local endpoint",
    )


def chat_for(config: TollgateConfig, role: RoleName) -> LangChainChat:
    model_id = getattr(config.llm.roles, role).model
    enforce_local_only(config, model_id)
    return LangChainChat(
        model_id,
        base_url=config.llm.base_url,
        temperature=config.llm.temperature,
    )


async def probe_role(config: TollgateConfig, role: RoleName) -> tuple[str, str, float, int | None]:
    model = chat_for(config, role)
    started = time.perf_counter()
    try:
        await structured_output(
            model,
            system="Reply with the schema.",
            user="ping",
            schema=Probe,
            mode=config.llm.structured_output,
        )
        used = "native" if model.supports_native else "json_prompt"
    except UnsupportedStructured:
        used = "json_prompt"
    except Exception as exc:
        raise ModelUnreachable(f"{role} {model.model_id}: {exc}") from exc
    elapsed = time.perf_counter() - started
    return model.model_id, used, elapsed, config.llm.context_window


def _split_model(model_id: str) -> tuple[str, str]:
    if ":" not in model_id:
        raise ConfigError("llm.roles", f"model {model_id!r} must be provider:model")
    provider, model = model_id.split(":", 1)
    return provider, model
