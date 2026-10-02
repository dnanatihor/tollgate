# Changelog

All notable changes to this project are documented here.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project uses [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- Repository created from SPEC.md.
- Phase 0 scaffold: configuration loading, standards catalogs, and `tollgate standards list`.
- Phase 1 local diff pipeline: classification, structural context, and dry-run unit planning.
- Phase 2 LLM layer: structured output with fallback, verification, ranking, verdict, and local Markdown, JSON, and SARIF.
- Phase 3 analyzers: layer, tech-radar, significance, contract, and migration checks, plus scanner coverage notes.
- Phase 4 GitHub publishing: batched reviews, summary state, SARIF, and fork read-only mode.
- Phase 5 Bitbucket Cloud publishing: comments, summary upsert, and Code Insights batches.
- Phase 6 Bitbucket Data Center 8.19 publishing: anchored comments, insights, and build status.
- Phase 7 evaluation harness, critic pass, nightly workflow, and the README.
- Phase 8 webhook service: HMAC checks and an in-process job queue.
- Dismissed findings stay in the report, GitHub check annotations are batched at 50, Data Center line types come from the diff, and the PR architecture pass drops unknown paths.
- `tollgate baseline` and `tollgate eval` exist. Semgrep, gitleaks, and OSV run when installed. Eval cases include TypeScript, Java, Go, and C#.
- Real-model eval can target `openai:gpt-4.1-mini`. Lens review and the architecture pass share one event loop.
