"""The critic can dismiss a finding so it no longer blocks."""

from __future__ import annotations

import json

import pytest

from tollgate.config import Critic, TollgateConfig
from tollgate.critic import apply_critic
from tollgate.llm.scripted import ScriptedChat
from tollgate.models import Finding
from tollgate.verdict import decide
from tollgate.verify import fingerprint


@pytest.mark.asyncio
async def test_reject_removes_the_finding_from_the_verdict() -> None:
    evidence = "query = order_id"
    finding = Finding(
        fingerprint=fingerprint("security", "app/orders.py", evidence, "CWE-89"),
        lens="security",
        title="SQL injection",
        severity="high",
        confidence="high",
        file="app/orders.py",
        start_line=2,
        end_line=2,
        evidence=evidence,
        explanation="Concatenated SQL.",
        recommendation="Parameterise it.",
        standards=("CWE-89",),
        sources=("llm:security",),
        corroborated=False,
        status="active",
    )
    model = ScriptedChat([json.dumps({"decision": "reject", "reason": "the value is a constant"})])
    config = TollgateConfig(critic=Critic(enabled=True, min_severity="high"))
    reviewed = await apply_critic([finding], model=model, config=config)
    assert reviewed[0].status == "dismissed_by_critic"
    assert decide(reviewed, config).outcome == "pass"


@pytest.mark.asyncio
async def test_secret_findings_are_not_sent_to_the_critic() -> None:
    evidence = "«secret»"
    finding = Finding(
        fingerprint=fingerprint("security", "app/settings.py", evidence, "OWASP-WEB-2025:A04"),
        lens="security",
        title="Hard-coded secret",
        severity="critical",
        confidence="high",
        file="app/settings.py",
        start_line=2,
        end_line=2,
        evidence=evidence,
        explanation="Masked.",
        recommendation="Remove it.",
        standards=("OWASP-WEB-2025:A04",),
        sources=("gitleaks",),
        corroborated=True,
        status="active",
    )
    model = ScriptedChat([])
    config = TollgateConfig(critic=Critic(enabled=True))
    reviewed = await apply_critic([finding], model=model, config=config)
    assert reviewed[0].status == "active"
    assert model.structured_calls == []
