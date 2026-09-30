# Tollgate — Enterprise-architect-level AI pull request reviewer

[![CI](https://img.shields.io/badge/CI-github%20actions-2ea44f)](./.github/workflows/ci.yml)

> **Status:** under construction. The design and build plan are in [SPEC.md](SPEC.md).

## Why

Security, architecture, and performance issues land in pull requests faster than a human review queue can cover them, and style bots do not cite the standards an organisation actually uses. Platform, security, and architecture teams on GitHub and Bitbucket need a reviewer that checks each change against OWASP, the organisation's own rules, and performance checks, and that publishes a finding only when the code can be anchored to a real line.

## Quickstart

Planned for Phase 7: one command that installs Tollgate and reviews a local repository. The CI workflow in [`.github/workflows/ci.yml`](./.github/workflows/ci.yml) is the Phase 0 check (`uv sync`, lint, type-check, tests).

## Licence

Apache-2.0. See [LICENSE](LICENSE).
