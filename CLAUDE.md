# encedo-wkd — CLAUDE.md

## Purpose
WKD (Web Key Directory) server for Encedo Mail — stdlib only, no external dependencies.
Serves OpenPGP public keys over HTTP so that email clients (ProtonMail, GPG, Thunderbird)
can automatically encrypt outgoing mail to recipients on hosted domains.

Same deployment pattern as `carbonio-oidc-connector`.

## Project layout
- `server.py` — entry point, ThreadingHTTPServer, all HTTP endpoints
- `wkd.py` — Z-Base-32 hash algorithm (SHA1 + custom alphabet), domain extraction
- `store.py` — disk cache (binary pubkey files per domain)
- `config.py` — loads `config.json` (path via `WKD_CONFIG` env var)
- `config.json.example` — template for deployment

## Key decisions
- Z-Base-32 alphabet (`ybndrfg8ejkmcpqxot1uwisza345h769`) differs from standard Base32 — do NOT mix them up.
- Cache files are raw binary OpenPGP pubkey packets (not ASCII-armored).
- Cache path: `cache_dir/<domain>/<zbase32hash>` (one file per key).
- No authentication on `/api/publish` in Phase 1 — TODO for Phase 4.
- Runs on port 8089 (127.0.0.1 only), nginx proxy in front.
- No external dependencies — stdlib only (no Flask, no pip).

## Config (config.json)
| Field      | Required | Default | Description          |
|------------|----------|---------|----------------------|
| port       | yes      | —       | Listening port       |
| cache_dir  | yes      | —       | Key storage root dir |
| host       | no       | 127.0.0.1 | Bind address       |
| log_file   | no       | /var/log/encedo-wkd.log | Log file      |
| log_level  | no       | INFO    | Python logging level |

## WKD endpoints
- `GET /.well-known/openpgpkey/<domain>/hu/<hash>` — advanced method
- `GET /.well-known/openpgpkey/hu/<hash>` — direct method (domain from Host header)
- `GET /.well-known/openpgpkey/[<domain>/]policy` — policy (empty 200)
- `POST /api/publish` — store a pubkey `{ email, pubkey_base64 }`
- `DELETE /api/revoke` — remove a pubkey `{ email }`

## Deploy (same pattern as carbonio-oidc-connector)
```bash
cp -r . /opt/encedo-wkd
cp config.json.example /opt/encedo-wkd/config.json
# edit config.json — set cache_dir, port, log_file
mkdir -p /var/encedo-wkd/cache
chown www-data:www-data /var/encedo-wkd/cache
cp encedo-wkd.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now encedo-wkd
```
