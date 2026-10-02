"""Verification, fingerprints, ranking, and the verdict matrix."""

from __future__ import annotations

from tollgate.config import TollgateConfig
from tollgate.llm.schemas import ProposedFinding
from tollgate.models import Finding
from tollgate.rank import rank_findings
from tollgate.standards import load_catalogs
from tollgate.verdict import decide
from tollgate.verify import fingerprint, known_ids_from_catalogs, verify_finding

FILE = (
    "def charge(order_id):\n"
    '    query = "SELECT * FROM orders WHERE id=" + order_id\n'
    "    return query\n"
)
ANNOTATED = (
    "L1   def charge(order_id):\n"
    'L2 +     query = "SELECT * FROM orders WHERE id=" + order_id\n'
    "L3   return query\n"
)
EVIDENCE = '    query = "SELECT * FROM orders WHERE id=" + order_id'
KNOWN = known_ids_from_catalogs(load_catalogs(), ("ORG:P02",))


def _proposed(**overrides: object) -> ProposedFinding:
    data: dict[str, object] = {
        "title": "SQL injection",
        "severity": "high",
        "confidence": "high",
        "start_line": 2,
        "end_line": 2,
        "evidence": EVIDENCE,
        "explanation": "The query concatenates a request value.",
        "recommendation": "Use a parameterised query.",
        "standards": ["OWASP-WEB-2025:A05", "CWE-89"],
    }
    data.update(overrides)
    return ProposedFinding.model_validate(data)


def test_hallucinated_line_and_invented_id_are_dropped() -> None:
    missing = verify_finding(
        _proposed(start_line=99, end_line=99),
        lens="security",
        path="app/orders.py",
        annotated=ANNOTATED,
        file_text=FILE,
        known_ids=KNOWN,
        web_prefix="OWASP-WEB-2025:",
    )
    invented = verify_finding(
        _proposed(standards=["OWASP-WEB-2025:A99"]),
        lens="security",
        path="app/orders.py",
        annotated=ANNOTATED,
        file_text=FILE,
        known_ids=KNOWN,
        web_prefix="OWASP-WEB-2025:",
    )
    downgraded = verify_finding(
        _proposed(severity="critical"),
        lens="security",
        path="app/orders.py",
        annotated=ANNOTATED,
        file_text=FILE,
        known_ids=KNOWN,
        web_prefix="OWASP-WEB-2025:",
    )
    assert missing is None
    assert invented is None
    assert downgraded is not None
    assert downgraded.severity == "high"


def test_mismatched_evidence_is_reanchored() -> None:
    finding = verify_finding(
        _proposed(start_line=1, end_line=1),
        lens="security",
        path="app/orders.py",
        annotated=ANNOTATED,
        file_text=FILE,
        known_ids=KNOWN,
        web_prefix="OWASP-WEB-2025:",
    )
    assert finding is not None
    assert finding.start_line == 2
    assert finding.end_line == 2


def test_standard_ids_with_appended_names_are_kept() -> None:
    finding = verify_finding(
        _proposed(
            standards=[
                "OWASP-WEB-2025:A05 Injection",
                "CWE-89 Improper Neutralization of Special Elements",
            ]
        ),
        lens="security",
        path="app/orders.py",
        annotated=ANNOTATED,
        file_text=FILE,
        known_ids=KNOWN,
        web_prefix="OWASP-WEB-2025:",
    )
    assert finding is not None
    assert finding.standards[0] == "OWASP-WEB-2025:A05"
    assert "CWE-89" in finding.standards


def test_patch_spanning_the_wrong_lines_is_removed() -> None:
    finding = verify_finding(
        _proposed(suggested_patch="line one\nline two\n"),
        lens="security",
        path="app/orders.py",
        annotated=ANNOTATED,
        file_text=FILE,
        known_ids=KNOWN,
        web_prefix="OWASP-WEB-2025:",
    )
    assert finding is not None
    assert finding.suggested_patch is None
    assert finding.title == "SQL injection"


def test_fingerprint_ignores_line_shifts() -> None:
    left = fingerprint("security", "app/orders.py", EVIDENCE, "OWASP-WEB-2025:A05")
    right = fingerprint("security", "app/orders.py", f"  {EVIDENCE}  ", "OWASP-WEB-2025:A05")
    assert left == right
    assert len(left) == 16


def test_verdict_and_inline_cap() -> None:
    first = verify_finding(
        _proposed(),
        lens="security",
        path="app/orders.py",
        annotated=ANNOTATED,
        file_text=FILE,
        known_ids=KNOWN,
        web_prefix="OWASP-WEB-2025:",
    )
    second = verify_finding(
        _proposed(title="Second issue", severity="medium", standards=["CWE-89"]),
        lens="security",
        path="app/orders.py",
        annotated=ANNOTATED,
        file_text=FILE,
        known_ids=KNOWN,
        web_prefix="OWASP-WEB-2025:",
    )
    assert first is not None and second is not None
    config = TollgateConfig(max_inline_comments=1, fail_on="critical")
    ranked = rank_findings([first, second], config)
    assert len(ranked.inline) == 1
    assert ranked.inline[0].severity == "high"
    assert decide([first], config).outcome == "concerns"
    assert decide([first], TollgateConfig(fail_on="high")).outcome == "block"

    critical = first.model_copy(update={"severity": "critical", "confidence": "high"})
    assert isinstance(critical, Finding)
    assert decide([critical], TollgateConfig()).outcome == "block"
