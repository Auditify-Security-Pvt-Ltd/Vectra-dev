"""
Cloud provider abstraction.

A provider is stateless: every call receives a ProviderSession carrying the
integration's validated configuration and decrypted credentials (in memory
only). Persistence, RBAC, auditing and sync orchestration live outside the
provider, so provider-specific logic never leaks into the rest of Vectra.

Lifecycle mapping
-----------------
    connect()             → parse_config() + validate_connection(), stored by cloud.store
    disconnect()          → cloud.store (credentials destroyed; findings kept)
    validate_connection() → validate_connection()
    get_account_info()    → ValidationResult.accountId / accountLabel
    fetch/sync findings   → fetch_findings() (paginated, normalized), orchestrated by cloud.sync
    list_assets()         → FetchResult.assets (resources referenced by findings)
    get_finding()         → served from Vectra's store, not re-fetched per finding
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Optional

from cloud.models import FetchResult, ValidationResult


@dataclass
class ProviderSession:
    org_id: str
    integration_id: str
    auth_method: str
    config: dict[str, Any]
    credentials: Optional[dict[str, Any]] = field(default=None, repr=False)  # never printed


@dataclass
class AuthMethod:
    key: str
    label: str
    description: str
    recommended: bool = False
    requires_secret: bool = False


class CloudProvider(ABC):
    key: str
    display_name: str
    security_service: str
    auth_methods: list[AuthMethod]
    # "available" | "derived" | "future"
    capabilities: dict[str, str]

    @abstractmethod
    def parse_config(
        self, auth_method: str, config: dict[str, Any], credentials: Optional[dict[str, Any]],
    ) -> tuple[dict[str, Any], Optional[dict[str, Any]]]:
        """Validate and sanitize user input. Raises ConfigurationError. Returns (config, credentials)."""

    @abstractmethod
    def validate_connection(self, session: ProviderSession) -> ValidationResult:
        """Live, read-only permission check. Never raises for provider errors."""

    @abstractmethod
    def fetch_findings(self, session: ProviderSession, max_findings: int) -> FetchResult:
        """Fetch every page of active findings, normalized. Partial failures are reported, not raised."""

    def setup_info(self, org_id: str) -> dict[str, Any]:
        """Non-secret setup instructions for the connect flow."""
        return {}

    def describe(self) -> dict[str, Any]:
        return {
            "key": self.key,
            "name": self.display_name,
            "securityService": self.security_service,
            "status": "available",
            "capabilities": self.capabilities,
            "authMethods": [m.__dict__ for m in self.auth_methods],
        }
