"""
Auth backends for encedo-wkd.

Each backend implements AuthBackend.authenticate() which receives the request
headers and the email from the request body, and returns either:
  (account_email, all_emails)  — on success
  (None, None)                 — on failure (caller sends 401)
"""

from abc import ABC, abstractmethod


class AuthBackend(ABC):
    """Abstract auth backend interface."""

    @abstractmethod
    def authenticate(self, headers, request_email: str) -> tuple[str, set[str]] | tuple[None, None]:
        """Validate the request and return (account, all_emails) or (None, None)."""

    def error_response(self) -> dict:
        """JSON body to send on 401. Backends may override."""
        return {"error": "authentication failed"}


def load_backend(config: dict) -> "AuthBackend":
    """Instantiate the auth backend named in config['auth_backend'].

    Supported values:
      'none'     — no authentication (standalone / CLI-only mode)
      'carbonio' — Carbonio SOAP token validation (default when carbonio_url is set)
    """
    name = config.get("auth_backend", "").strip()

    # Legacy: if auth_backend not set but carbonio_url is present, use carbonio
    if not name:
        name = "carbonio" if config.get("carbonio_url", "").strip() else "none"

    if name == "none":
        from auth.none import NoAuthBackend
        return NoAuthBackend()
    elif name == "carbonio":
        from auth.carbonio import CarbonicAuthBackend
        carbonio_url = config.get("carbonio_url", "").strip()
        if not carbonio_url:
            raise ValueError("auth_backend='carbonio' requires carbonio_url in config")
        return CarbonicAuthBackend(carbonio_url)
    else:
        raise ValueError(f"Unknown auth_backend: {name!r}. Supported: 'none', 'carbonio'")
