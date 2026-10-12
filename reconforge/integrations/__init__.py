"""Third-party API clients. All keys come from ScanContext; failures raise."""

from __future__ import annotations


class IntegrationError(RuntimeError):
    """A third-party API call failed in a non-retryable way."""
