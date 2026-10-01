"""
Provider errors with user-safe messages.

Connectors translate SDK/HTTP exceptions into CloudProviderError so no raw
provider response, stack trace or credential material ever reaches a client.
"""
from __future__ import annotations


class CloudProviderError(Exception):
    """A provider call failed. `message` and `hint` are safe to show to users."""

    INVALID_CREDENTIALS   = "INVALID_CREDENTIALS"
    ACCESS_DENIED         = "ACCESS_DENIED"
    SERVICE_NOT_ENABLED   = "SERVICE_NOT_ENABLED"
    INVALID_CONFIGURATION = "INVALID_CONFIGURATION"
    THROTTLED             = "THROTTLED"
    TIMEOUT               = "TIMEOUT"
    MALFORMED_RESPONSE    = "MALFORMED_RESPONSE"
    PROVIDER_ERROR        = "PROVIDER_ERROR"
    NOT_CONFIGURED        = "NOT_CONFIGURED"

    RETRYABLE = {THROTTLED, TIMEOUT, PROVIDER_ERROR}

    def __init__(self, code: str, message: str, hint: str | None = None, reason: str | None = None):
        super().__init__(code)
        self.code = code
        self.message = message
        self.hint = hint
        # Provider-specific typed reason (e.g. GCP_API_DISABLED). `code` stays
        # the provider-neutral category the sync engine and UI already rely on.
        self.reason = reason

    @property
    def retryable(self) -> bool:
        return self.code in self.RETRYABLE

    def to_dict(self) -> dict:
        out = {"code": self.code, "message": self.message, "hint": self.hint}
        if self.reason:
            out["reason"] = self.reason
        return out


class ConfigurationError(ValueError):
    """Invalid integration input supplied by the user (maps to HTTP 400)."""
