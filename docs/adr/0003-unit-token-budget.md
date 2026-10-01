# 0003 — Review unit token budget

- Status: accepted
- Date: 2026-09-30

## Context

SPEC.md §7.4 says a unit is one file's hunks, split when the hunks exceed the unit token budget. It does not give that number. Token estimates follow §9.3: characters divided by 3.5, then a 15% margin, until a tokenizer is selected for a model.

## Options considered

1. A fixed 8,000-token unit budget, independent of the model context window.
2. A fraction of `llm.context_window` when set, with no split when the window is unknown.
3. Never split a file.

## Decision

Option 1. A unit is split by annotated lines once its estimate exceeds 8,000 tokens. Files are then chosen in risk order until `limits.max_files`, `limits.max_changed_lines`, and `llm.budget.max_input_tokens_per_pr` are spent. The dry run prints every selected unit and names what was not reviewed.

## Consequences

Very large hunks become several units with the same structural context. Organisations change the pull-request budget in `.tollgate.yml`; the per-unit cap stays in the planner until a model-specific window is known.
