# 0006 — Webhook signature algorithms

- Status: accepted
- Date: 2026-09-30

## Context

Phase 8 accepts webhooks from GitHub and Bitbucket. This checkout cannot register a GitHub App or a Bitbucket webhook, so the spike checked the published signature schemes rather than a live delivery.

## Options considered

1. GitHub `X-Hub-Signature-256`: `sha256=` plus hex HMAC-SHA256 of the raw body with the webhook secret.
2. Bitbucket Cloud `X-Hub-Signature`: the same `sha256=` HMAC over the raw body with the webhook secret.
3. Bitbucket Connect JWT — used by Connect apps, not by a plain repository webhook.

## Decision

Verify GitHub with `X-Hub-Signature-256` and Bitbucket Cloud with `X-Hub-Signature`. Both are HMAC-SHA256 of the raw request body. Compare with a constant-time check. Reject a missing or wrong signature before a job is queued. Data Center webhooks that send the same `X-Hub-Signature` header use the same function.

## Consequences

A real GitHub App still has to mint installation tokens and complete an end-to-end review. The service in this repository proves the signature and the in-process queue only.
