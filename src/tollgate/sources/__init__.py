"""Content sources for a pull request diff."""

from tollgate.sources.local_git import LocalGitSource, load_local_git

__all__ = ["LocalGitSource", "load_local_git"]
