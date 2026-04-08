"""
NoAuth backend — no authentication required.

Use in standalone mode (no mail server) where the WKD port is not
exposed externally and keys are managed via wkd-cli or direct API calls
from localhost.
"""

import logging
from auth import AuthBackend

log = logging.getLogger(__name__)


class NoAuthBackend(AuthBackend):

    def authenticate(self, headers, request_email: str) -> tuple[str, set[str]] | tuple[None, None]:
        client_ip = getattr(headers, "_client_ip", "?")
        log.warning(
            "auth DISABLED (backend=none) — request for %r from %s allowed without authentication",
            request_email, client_ip,
        )
        return request_email, {request_email}

    def error_response(self) -> dict:
        return {"error": "authentication failed"}
