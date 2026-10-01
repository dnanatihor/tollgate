"""Fan out one review call per unit and lens with LangGraph ``Send``."""

from __future__ import annotations

import operator
from typing import Annotated, Any, TypedDict

from langgraph.graph import END, START, StateGraph
from langgraph.types import Send


class GraphState(TypedDict):
    jobs: list[dict[str, Any]]
    results: Annotated[list[Any], operator.add]


def _fan(state: GraphState) -> list[Send]:
    return [Send("review", {"job": job}) for job in state["jobs"]]


async def _review(state: dict[str, Any]) -> dict[str, list[Any]]:
    job = state["job"]
    produced = await job["runner"](job)
    return {"results": produced}


def compile_review_graph() -> Any:
    builder: StateGraph[GraphState] = StateGraph(GraphState)
    builder.add_node("review", _review)  # type: ignore[type-var]
    builder.add_conditional_edges(START, _fan, ["review"])
    builder.add_edge("review", END)
    return builder.compile()
