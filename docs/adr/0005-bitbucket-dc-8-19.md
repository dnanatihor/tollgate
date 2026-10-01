# 0005 — Bitbucket Data Center 8.19 comment anchors

- Status: accepted
- Date: 2026-09-30

## Context

Phase 6 needs a target Data Center version before the provider sends comment anchors. This checkout has no Data Center instance, so the spike checked Atlassian's 8.19 javadoc and the REST comment shape used with that release, not a running server.

## Options considered

1. Data Center 8.19 — `CommentThreadDiffAnchor` documents `lineType` ADDED, REMOVED, and CONTEXT, with fileType TO for added lines and either side for context.
2. Data Center 10.x — the same anchor fields still exist, but it is a newer major version than the one most enterprises are upgrading from.
3. Guess a payload without a version — rejected. The spec requires the spike to name a version.

## Decision

Target Bitbucket Data Center 8.19. Inline comments POST to `/rest/api/1.0/projects/{project}/repos/{slug}/pull-requests/{id}/comments` with `anchor.lineType` of `ADDED` for `+` lines and `CONTEXT` for context lines, `fileType: TO`, and `diffType: EFFECTIVE`. Summary updates send the comment `version`. Authentication is `Authorization: Bearer`. Code Insights use `/rest/insights/1.0/...` and build status uses `/rest/build-status/1.0/commits/{commit}`.

There is no Jenkins controller in this environment. The example in `jenkins/Jenkinsfile` matches that API and is covered by the mocked tests, not by a live build.

## Consequences

Upgrading the target past 8.19 means re-checking anchor behaviour. A live Data Center still has to be used before the Jenkins job is treated as proven in a real project.
