"""Model-facing helpers. The chat client arrives in Phase 2."""

from tollgate.llm.redact import mask_secrets

__all__ = ["mask_secrets"]
