"""SARIF 2.1.0 rendering."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import jsonschema

from tollgate import __version__
from tollgate.models import Finding, Verdict

_LEVEL = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
}


def render_sarif(findings: list[Finding], verdict: Verdict) -> str:
    rules: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []
    for finding in findings:
        rule_id = finding.standards[0] if finding.standards else finding.lens
        rules.setdefault(
            rule_id,
            {
                "id": rule_id,
                "shortDescription": {"text": finding.title},
                "helpUri": "https://owasp.org/Top10/2025/",
            },
        )
        result: dict[str, Any] = {
            "ruleId": rule_id,
            "level": _LEVEL[finding.severity],
            "message": {"text": finding.explanation},
            "properties": {
                "fingerprint": finding.fingerprint,
                "verdict": verdict.outcome,
            },
        }
        if finding.file and finding.start_line is not None:
            region: dict[str, int] = {"startLine": finding.start_line}
            if finding.end_line is not None:
                region["endLine"] = finding.end_line
            result["locations"] = [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": finding.file},
                        "region": region,
                    }
                }
            ]
        results.append(result)
    document: dict[str, Any] = {
        "$schema": (
            "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/"
            "master/Schemata/sarif-schema-2.1.0.json"
        ),
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Tollgate",
                        "version": __version__,
                        "informationUri": "https://owasp.org/Top10/2025/",
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
            }
        ],
    }
    return json.dumps(document, indent=2) + "\n"


def validate_sarif(document: str) -> None:
    schema_path = Path(__file__).resolve().parent / "sarif-schema-2.1.0.json"
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    validator = jsonschema.Draft7Validator(schema)
    errors = sorted(validator.iter_errors(json.loads(document)), key=str)
    if errors:
        raise ValueError(errors[0].message)
