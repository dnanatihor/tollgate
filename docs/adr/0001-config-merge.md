# 0001 — Configuration merge and locked keys

- Status: accepted
- Date: 2026-09-30

## Context

SPEC.md §5.3 requires an organisation file (`TOLLGATE_ORG_CONFIG`, a path or URL) merged underneath the repository `.tollgate.yml`, with keys listed under `locked:` in the org file that cannot be overridden. It also requires configuration to be read from the PR base ref, and invalid configuration to fail with exit code 2 naming the key. It does not define the syntax of `locked` entries, how nested mappings and lists merge, or whether an equal value counts as an override.

## Options considered

1. Dotted paths (`llm.local_only`), deep-merge mappings, replace lists, and reject a repository value that differs — the error names that path.
2. Silently keep the organisation value when a locked key is also set in the repository, so a pull request cannot tell that its override was ignored.
3. Treat `locked` as a map of values rather than a list of paths.

## Decision

Option 1. `locked` is a list of dotted paths into `.tollgate.yml`. Mappings merge recursively; lists and scalars in the repository replace the organisation value. A locked path whose repository value differs from the organisation value is a configuration error that names the path. The same value is not an override. Only the organisation file may contain `locked`; the repository file is the schema in §5.1. Architecture rules in `.tollgate/architecture.yaml` are read from the base ref and are not part of the organisation overlay.

`tollgate standards list` reads the catalogs shipped with Tollgate and, when present, organisation principle and guideline ids from the working tree. Review commands read both files from the base ref, never from the PR head.

## Consequences

Organisation policy can freeze `fail_on`, lens toggles, and similar keys by listing their paths. List fields such as `paths.exclude` cannot be extended piecemeal: the repository replaces the whole list when it sets the key. A later change can add explicit list-merge keys if organisations need that.
