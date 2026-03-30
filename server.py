#!/usr/bin/env python3
"""
Encedo WKD Server — Web Key Directory for OpenPGP public keys.
No external dependencies — stdlib only.
"""

import http.server
import json
import logging
import logging.handlers
import os
import re
import signal
import socketserver
import sys
import threading
import urllib.request
from urllib.parse import urlparse, parse_qs

sys.path.insert(0, os.path.dirname(__file__))

import config as cfg
import store
from wkd import wkd_hash, extract_domain

VERSION = "1.0.0"

_cfg = {}

log = logging.getLogger(__name__)

EMAIL_RE = re.compile(r'^[^@\s]+@[^@\s]+\.[^@\s]+$')


def _validate_carbonio_token(token: str, carbonio_url: str) -> str | None:
    """Validate a Carbonio auth token via SOAP GetInfoRequest.

    Returns the authenticated account email address on success, or None
    if the token is invalid, expired, or the request fails.
    """
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
                "sections": "mbox",
            }
        },
    }).encode("utf-8")

    req = urllib.request.Request(
        f"{carbonio_url}/service/soap/GetInfoRequest",
        data=soap_body,
        headers={"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read())
            return data.get("Body", {}).get("GetInfoResponse", {}).get("name")
    except Exception as exc:
        log.warning("Carbonio token validation failed: %s", exc)
        return None

# Route patterns
# Advanced method:  /.well-known/openpgpkey/<domain>/hu/<hash>
# Advanced policy:  /.well-known/openpgpkey/<domain>/policy
# Direct method:    /.well-known/openpgpkey/hu/<hash>
# Direct policy:    /.well-known/openpgpkey/policy
# API publish:      /api/publish   POST
# API revoke:       /api/revoke    DELETE

_RE_ADVANCED_KEY    = re.compile(r'^/\.well-known/openpgpkey/([^/]+)/hu/([^/?]+)')
_RE_ADVANCED_POLICY = re.compile(r'^/\.well-known/openpgpkey/([^/]+)/policy$')
_RE_DIRECT_KEY      = re.compile(r'^/\.well-known/openpgpkey/hu/([^/?]+)')
_RE_DIRECT_POLICY   = re.compile(r'^/\.well-known/openpgpkey/policy$')


def setup_logging(log_file: str, log_level: str) -> None:
    level = getattr(logging, log_level.upper(), logging.INFO)
    fmt = logging.Formatter(
        fmt="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    root = logging.getLogger()
    root.setLevel(level)
    stderr = logging.StreamHandler(sys.stderr)
    stderr.setFormatter(fmt)
    root.addHandler(stderr)
    try:
        fh = logging.FileHandler(log_file, encoding="utf-8")
        fh.setFormatter(fmt)
        root.addHandler(fh)
    except OSError as e:
        root.warning("Cannot open log file %s: %s — logging to stderr only", log_file, e)


class WKDHandler(http.server.BaseHTTPRequestHandler):

    # ------------------------------------------------------------------ GET

    def do_GET(self):
        path = urlparse(self.path).path

        m = _RE_ADVANCED_KEY.match(path)
        if m:
            self._serve_key(m.group(1), m.group(2))
            return

        m = _RE_ADVANCED_POLICY.match(path)
        if m:
            self._serve_policy()
            return

        m = _RE_DIRECT_KEY.match(path)
        if m:
            domain = extract_domain(self)
            self._serve_key(domain, m.group(1))
            return

        if _RE_DIRECT_POLICY.match(path):
            self._serve_policy()
            return

        self._send_json(404, {"error": "not_found"})

    # ----------------------------------------------------------------- POST

    def do_POST(self):
        if urlparse(self.path).path == "/api/publish":
            self._handle_publish()
        else:
            self._send_json(404, {"error": "not_found"})

    # --------------------------------------------------------------- DELETE

    def do_DELETE(self):
        if urlparse(self.path).path == "/api/revoke":
            self._handle_revoke()
        else:
            self._send_json(404, {"error": "not_found"})

    # ---------------------------------------------------------------- WKD responses

    def _serve_key(self, domain: str, hash_: str) -> None:
        data = store.get_key(domain, hash_)
        if data is None:
            self.send_response(404)
            self.end_headers()
            return
        self.send_response(200)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(data)

    def _serve_policy(self) -> None:
        self.send_response(200)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Length", "0")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()

    # ---------------------------------------------------------------- API handlers

    def _handle_publish(self) -> None:
        body = self._read_json()
        if body is None:
            return

        email = body.get("email", "").strip().lower()
        pubkey_b64 = body.get("pubkey_base64", "").strip()

        if not EMAIL_RE.match(email):
            self._send_json(400, {"error": "invalid email"})
            return
        if not pubkey_b64:
            self._send_json(400, {"error": "missing pubkey_base64"})
            return

        account = self._require_auth(email)
        if account is None:
            return

        # User may only publish their own key
        if email != account:
            self._send_json(403, {"error": "forbidden: email does not match authenticated account"})
            return

        try:
            pubkey_bytes = store.decode_pubkey(pubkey_b64)
        except Exception:
            self._send_json(400, {"error": "invalid base64"})
            return

        local, domain = email.split("@", 1)
        hash_ = wkd_hash(local)
        store.put_key(domain, hash_, pubkey_bytes)
        log.info("published key for %s (hash=%s)", email, hash_)
        self._send_json(200, {"ok": True, "hash": hash_})

    def _handle_revoke(self) -> None:
        body = self._read_json()
        if body is None:
            return

        email = body.get("email", "").strip().lower()
        if not EMAIL_RE.match(email):
            self._send_json(400, {"error": "invalid email"})
            return

        account = self._require_auth(email)
        if account is None:
            return

        # User may only revoke their own key
        if email != account:
            self._send_json(403, {"error": "forbidden: email does not match authenticated account"})
            return

        local, domain = email.split("@", 1)
        hash_ = wkd_hash(local)
        deleted = store.delete_key(domain, hash_)
        if not deleted:
            self._send_json(404, {"error": "key not found"})
            return
        self._send_json(200, {"ok": True})

    # ---------------------------------------------------------------- helpers

    def _require_auth(self, request_email: str = "") -> str | None:
        """Validate X-Auth-Token via Carbonio SOAP GetInfoRequest.

        If carbonio_url is not set in config, auth is disabled and the
        request_email is returned as-is (unauthenticated / local mode).

        Returns authenticated account email on success, or sends 401 and
        returns None on failure.
        """
        carbonio_url = _cfg.get("carbonio_url", "").strip()
        if not carbonio_url:
            log.debug("auth disabled (carbonio_url not configured) — allowing request for %s", request_email)
            return request_email

        token = self.headers.get("X-Auth-Token", "").strip()
        if not token:
            self._send_json(401, {"error": "missing X-Auth-Token"})
            return None

        account = _validate_carbonio_token(token, carbonio_url)
        if account is None:
            self._send_json(401, {"error": "invalid or expired auth token"})
            return None
        return account

    def _read_json(self):
        length = int(self.headers.get("Content-Length", 0))
        if length == 0:
            self._send_json(400, {"error": "empty body"})
            return None
        try:
            return json.loads(self.rfile.read(length))
        except json.JSONDecodeError:
            self._send_json(400, {"error": "invalid JSON"})
            return None

    def _send_json(self, code: int, data: dict) -> None:
        body = json.dumps(data).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    # silence default BaseHTTPRequestHandler stderr logs — use our logger
    def log_message(self, format, *args):  # noqa: A002
        log.info("%s - %s", self.address_string(), format % args)


class ThreadingHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True


def main():
    logging.basicConfig(
        level=logging.DEBUG,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
        stream=sys.stderr,
    )

    config = cfg.load_config()

    logging.getLogger().handlers.clear()
    setup_logging(
        config.get("log_file", "/var/log/encedo-wkd.log"),
        config.get("log_level", "INFO"),
    )

    global _cfg
    _cfg = config

    store.init(config["cache_dir"])

    host = config.get("host", "127.0.0.1")
    port = int(config["port"])

    server = ThreadingHTTPServer((host, port), WKDHandler)

    def _shutdown(signum, frame):
        log.info("Received signal %s — shutting down", signum)
        t = threading.Thread(target=server.shutdown, daemon=True)
        t.start()

    signal.signal(signal.SIGTERM, _shutdown)
    signal.signal(signal.SIGINT, _shutdown)

    log.info("encedo-wkd %s listening on %s:%s", VERSION, host, port)
    server.serve_forever()
    log.info("Server stopped.")


if __name__ == "__main__":
    main()
