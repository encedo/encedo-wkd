"""
Carbonio auth backend — validates Carbonio session tokens via SOAP GetInfoRequest.

Accepts token from:
  - X-Auth-Token request header
  - ZM_AUTH_TOKEN cookie (HttpOnly — JS cannot read it, server reads it directly)

On success returns (account_email, all_emails) where all_emails includes the
primary address plus all aliases (zimbraMailAlias, zimbraAllowFromAddress).
"""

import json
import logging
import urllib.error
import urllib.request
from auth import AuthBackend

log = logging.getLogger(__name__)


class CarbonicAuthBackend(AuthBackend):

    def __init__(self, carbonio_url: str) -> None:
        self.carbonio_url = carbonio_url.rstrip("/")

    def authenticate(self, headers, request_email: str) -> tuple[str, set[str]] | tuple[None, None]:
        token = self._extract_token(headers)
        if not token:
            client_ip = getattr(headers, "_client_ip", "?")
            origin = headers.get("Origin", "") if hasattr(headers, "get") else ""
            log.warning("auth: missing X-Auth-Token / ZM_AUTH_TOKEN cookie from client=%s origin=%r", client_ip, origin)
            return None, None

        return self._validate_token(token)

    def error_response(self) -> dict:
        return {"error": "missing X-Auth-Token"}

    # ------------------------------------------------------------------ helpers

    def _extract_token(self, headers) -> str:
        if not hasattr(headers, "get"):
            return ""
        token = headers.get("X-Auth-Token", "").strip()
        if not token:
            cookie_hdr = headers.get("Cookie", "")
            for part in cookie_hdr.split(";"):
                name, _, val = part.strip().partition("=")
                if name.strip() == "ZM_AUTH_TOKEN":
                    token = val.strip()
                    break
        return token

    def _validate_token(self, token: str) -> tuple[str, set[str]] | tuple[None, None]:
        soap_url = f"{self.carbonio_url}/service/soap/GetInfoRequest"
        log.debug("token validation: POST %s (token prefix: %s…)", soap_url, token[:12] if token else "(empty)")

        soap_body = json.dumps({
            "Header": {
                "context": {
                    "_jsns": "urn:zimbra",
                    "authToken": {"_content": token},
                }
            },
            "Body": {
                "GetInfoRequest": {
                    "_jsns": "urn:zimbraAccount",
                    "sections": "mbox,attrs",
                }
            },
        }).encode("utf-8")

        req = urllib.request.Request(
            soap_url,
            data=soap_body,
            headers={"Content-Type": "application/json"},
        )
        try:
            with urllib.request.urlopen(req, timeout=5) as resp:
                data = json.loads(resp.read())
                fault = data.get("Body", {}).get("Fault")
                if fault:
                    reason = fault.get("Reason", {}).get("Text", "unknown fault")
                    log.warning("token validation: Carbonio SOAP fault — %s", reason)
                    return None, None
                info = data.get("Body", {}).get("GetInfoResponse", {})
                name = info.get("name")
                if not name:
                    log.warning("token validation: unexpected SOAP response structure: %s",
                                list(data.get("Body", {}).keys()))
                    return None, None

                all_emails: set[str] = {name.lower()}
                attrs = info.get("attrs", {}).get("_attrs", {})
                for attr_name in ("zimbraMailAlias", "zimbraAllowFromAddress"):
                    val = attrs.get(attr_name)
                    if isinstance(val, str):
                        all_emails.add(val.lower())
                    elif isinstance(val, list):
                        for v in val:
                            if isinstance(v, str):
                                all_emails.add(v.lower())

                log.debug("token validation: OK, account=%s aliases=%s", name, all_emails - {name.lower()})
                return name, all_emails

        except urllib.error.HTTPError as exc:
            body = exc.read(512).decode(errors="replace")
            log.warning("token validation: HTTP %s from %s — %s", exc.code, soap_url, body)
            return None, None
        except Exception as exc:
            log.warning("token validation: request to %s failed — %s", soap_url, exc)
            return None, None
