# Bitbucket Data Center

The target is Data Center 8.19. See `docs/adr/0005-bitbucket-dc-8-19.md`.

There is no Data Center or Jenkins controller in this checkout. `jenkins/Jenkinsfile` is the job shape, and `tests/test_bitbucket_dc.py` checks the comment anchor, including `lineType` `ADDED` and `CONTEXT`, plus the summary `version` field. That is the verification of the spike, not a screenshot from a live instance.
