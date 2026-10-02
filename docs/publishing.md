# Publishing to PyPI

The distribution name on PyPI is **`tollgate-review`**. The top-level name
`tollgate` is already taken by another project. The import and CLI stay
`import tollgate` and `tollgate …`.

## One-time PyPI setup (Trusted Publishing)

1. Create a PyPI account at <https://pypi.org>.
2. Create a new project (or claim `tollgate-review` on the first upload).
3. On the project → **Publishing** → **Add a new pending publisher**:
   - Owner: `dnanatihor`
   - Repository: `tollgate`
   - Workflow: `publish.yml`
   - Environment: `pypi`
4. In the GitHub repo, create an Environment named `pypi` (Settings → Environments).
   Optional: restrict it to tags matching `v*`.

No PyPI API token is stored in GitHub when Trusted Publishing is used. The
workflow requests an OpenID Connect token (`id-token: write`) and `uv publish`
exchanges it for a short-lived upload credential.

## Release steps

1. Set the version in `pyproject.toml` (for example `0.1.0`).
2. Move `[Unreleased]` notes into a dated section in `CHANGELOG.md`.
3. Commit, then tag and push:

```bash
git tag v0.1.0
GIT_SSH_COMMAND='ssh -o IdentitiesOnly=yes -i ~/.ssh/id_ed25519_personal' \
  git push origin v0.1.0
```

4. The `Publish` workflow builds the wheel and sdist, uploads to PyPI, and
   creates a GitHub Release with the artifacts.

Dry-run from Actions → Publish → Run workflow with **dry_run** checked to build
without uploading.

## Install after publish

```bash
pip install tollgate-review
# or
uv add tollgate-review
uv run tollgate --help
```
