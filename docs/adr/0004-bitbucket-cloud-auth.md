# 0004 — Bitbucket Cloud token and Code Insights limits

- Status: accepted
- Date: 2026-09-30

## Context

Phase 5 needs a token type, a way to authenticate Code Insights from Pipelines, and the annotation batch limit. This checkout has no Bitbucket workspace credentials, so the spike is against Atlassian's current public documentation, not a live repository.

Sources read on 2026-09-30:

- https://support.atlassian.com/bitbucket-cloud/docs/code-insights/
- https://developer.atlassian.com/cloud/bitbucket/rest/api-group-reports/
- https://support.atlassian.com/bitbucket-cloud/docs/repository-access-token-permissions/
- https://support.atlassian.com/bitbucket-cloud/docs/api-token-permissions/

## Options considered

1. Repository access token (Bearer) — scoped to one repository. Pull-request write is required to create comments; repository read is required for reports from outside Pipelines.
2. User API token — newer user-scoped credentials. They need separate repository and pull-request permissions and are broader than a repository token.
3. App passwords — legacy. Atlassian is replacing them with API tokens, so a new pipe should not depend on them.

## Decision

Use a repository access token in `BITBUCKET_ACCESS_TOKEN` for pull-request comments. Inside Pipelines, publish Code Insights through the proxy at `http://localhost:29418`, which adds authentication itself. Outside Pipelines, reports use the same token against `https://api.bitbucket.org/2.0`.

Annotation uploads use `POST .../reports/{report_id}/annotations` with at most 100 annotations per request. A report holds at most 1000. Inline comments stay one request each; Bitbucket Cloud's comment API has no GitHub-style `REQUEST_CHANGES` review event, so `request_changes` mode fails the pipeline via the process exit code and does not call a separate review API.

## Consequences

A live pull request with screenshots is still required before relying on the pipe in a workspace. The mocked tests follow this documented contract. Revisit the token choice if Atlassian retires repository access tokens.
