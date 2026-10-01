# Bitbucket Cloud manual run

This checkout has no Bitbucket workspace credentials, so a live pull request was not opened and there are no screenshots.

What was verified instead, on 2026-09-30:

- Auth and batch limits are recorded in `docs/adr/0004-bitbucket-cloud-auth.md` from Atlassian's Code Insights and token documentation.
- `tests/test_bitbucket_cloud.py` posts one inline comment (`inline.to` on the new-side line), updates the summary comment that contains `<!-- tollgate:summary -->`, posts no second inline comment for the same fingerprint, and uploads annotations in batches of 100.

To run it on a real repository later: create a repository access token with pull-request write, store it as `BITBUCKET_ACCESS_TOKEN`, use a full-depth clone, and add the pull-request pipe from `bitbucket-pipelines.yml`. Inside Pipelines, Code Insights go through `http://localhost:29418`.
