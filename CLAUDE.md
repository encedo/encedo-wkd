# encedo-wkd — CLAUDE.md

## Purpose
WKD (Web Key Directory) server for Encedo Mail — stdlib only, no external dependencies.
Serves OpenPGP public keys over HTTP so that email clients (ProtonMail, GPG, Thunderbird)
can automatically encrypt outgoing mail to recipients on hosted domains.

## Project layout
- `server.py` — entry point, ThreadingHTTPServer, all HTTP endpoints
- `wkd.py` — Z-Base-32 hash algorithm (SHA1 + custom alphabet), domain extraction
- `store.py` — disk cache (binary pubkey files per domain)
- `config.py` — loads `config.json` (path via `WKD_CONFIG` env var)
- `wkd_cli.py` — CLI admin tool: publish/revoke/list/show (direct store access, no server needed)
- `auth/__init__.py` — `AuthBackend` ABC + `load_backend(config)` factory
- `auth/none.py` — `NoAuthBackend` (standalone/CLI-only mode)
- `auth/carbonio.py` — `CarbonicAuthBackend` (SOAP GetInfoRequest, supports aliases)
- `install.sh` — full installation on a new server
- `encedo-wkd-nginx-inject.sh` — nginx config + TLS certs; re-run after new domain or Carbonio upgrade
- `nginx/upstream-wkd.conf` — installed to `/opt/zextras/conf/nginx/extensions/`
- `nginx/backend-wkd.conf` — installed to `/opt/zextras/conf/nginx/extensions/`

## Key decisions
- Z-Base-32 alphabet (`ybndrfg8ejkmcpqxot1uwisza345h769`) differs from standard Base32 — do NOT mix them up.
- Cache files are raw binary OpenPGP pubkey packets (not ASCII-armored).
- Cache path: `cache_dir/<domain>/<zbase32hash>` (one file per key).
- Runs on port 8089 (127.0.0.1 only), nginx proxy in front.
- No external dependencies — stdlib only (no Flask, no pip).

## Authentication
Auth is pluggable via `auth_backend` in config (or auto-detected from `carbonio_url`):
- **`carbonio`** (`carbonio_url` set): requires `X-Auth-Token` header (Carbonio session token).
  Validates via Carbonio SOAP `GetInfoRequest`. Also accepts `ZM_AUTH_TOKEN` cookie.
  Returns primary email + all aliases (`zimbraMailAlias`, `zimbraAllowFromAddress`).
  User may publish/revoke for any of their aliases, not only the primary address.
- **`none`** (`carbonio_url` empty): no auth. Only accessible on 127.0.0.1:8089.

To add a new auth backend: create `auth/mybackend.py` implementing `AuthBackend`,
register it in `auth/__init__.py:load_backend()`.

## Config (config.json)
| Field | Required | Default | Description |
|-------|----------|---------|-------------|
| `port` | yes | — | Listening port |
| `cache_dir` | yes | — | Key storage root dir |
| `host` | no | `127.0.0.1` | Bind address |
| `log_file` | no | `/var/log/encedo-wkd.log` | Log file |
| `log_level` | no | `INFO` | Python logging level |
| `auth_backend` | no | auto | `"carbonio"` or `"none"` (auto-detected from `carbonio_url`) |
| `carbonio_url` | no | `""` | Required when `auth_backend=carbonio` |

## wkd-cli
Direct admin tool — no server required, no auth:
```bash
python3 wkd_cli.py publish --email jan@firma.pl --key pub.asc
python3 wkd_cli.py revoke  --email jan@firma.pl
python3 wkd_cli.py list    [--domain firma.pl]
python3 wkd_cli.py show    --email jan@firma.pl
python3 wkd_cli.py hash    --email jan@firma.pl
```
Reads `cache_dir` from the same `config.json` as the server.

## WKD endpoints
- `GET /.well-known/openpgpkey/<domain>/hu/<hash>` — advanced method
- `GET /.well-known/openpgpkey/hu/<hash>` — direct method (domain from Host header)
- `GET /.well-known/openpgpkey/[<domain>/]policy` — policy (empty 200)
- `POST /api/publish` — store a pubkey `{ email, pubkey_base64 }` (auth required in production)
- `DELETE /api/revoke` — remove a pubkey `{ email }` (auth required in production)

## nginx architecture
```
openpgpkey.<domain>:443 (Let's Encrypt cert)
  → proxy → 127.0.0.1:8089
  → /.well-known/openpgpkey/... → WKD lookup (public, no auth)

mailserver.encedo.com:443
  → /wkd/ → 127.0.0.1:8089
  → /api/publish, /api/revoke → WKD management (Carbonio auth required)
```

`encedo-wkd-nginx-inject.sh` generates `nginx.conf.web.https` with `listen <IP>:443`
(not `*:443`) — must use same socket as Carbonio default_server for SNI routing.

## Deploy / update
```bash
sudo ./install.sh                    # full install
sudo bash encedo-wkd-nginx-inject.sh # nginx config + TLS (re-run after domain changes)
sudo systemctl restart encedo-wkd
```
