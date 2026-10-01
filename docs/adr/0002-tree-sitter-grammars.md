# 0002 — Tree-sitter grammar bundle

- Status: accepted
- Date: 2026-09-30

## Context

SPEC.md Phase 1 requires structural context for common languages through a maintained multi-language tree-sitter bundle, verified by a spike before code depends on it. Reviews and tests must run without a network fetch.

## Options considered

1. `tree-sitter-language-pack` 1.20.0 — one package, 371 language names. `language_count()` was 0 after install. `get_parser("python")` downloaded the grammar (about 40 seconds in the spike) and then reported the language as downloaded. The wheel does not contain the grammars.
2. `tree-sitter-languages` 1.10.2 — an older all-in-one binary wheel with an unpinned `tree-sitter` dependency. It is not the grammar line published with current `tree-sitter` 0.26 bindings.
3. Official per-language wheels (`tree-sitter-python` 0.25.0, `tree-sitter-javascript` 0.25.0, `tree-sitter-typescript` 0.23.2, `tree-sitter-java` 0.23.5, `tree-sitter-go` 0.25.0, `tree-sitter-c-sharp` 0.23.5) on `tree-sitter` 0.26.0. Each wheel contains its compiled grammar. A sample of Python, JavaScript, TypeScript, Java, Go, and C# parsed offline with no syntax error on the root node.

## Decision

Option 3. These six grammars are the structural-context bundle. Any other language uses the ±30-line window and the first 40 lines of the file, and a missing or failing parser takes that same path instead of raising.

## Consequences

Adding a language means adding its official wheel and a node-type map. CI does not download grammars. The language-pack can be reconsidered if it ships the grammars inside the wheel.
