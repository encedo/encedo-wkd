# encedo-wkd

WKD (Web Key Directory, [RFC draft](https://datatracker.ietf.org/doc/draft-koch-openpgp-webkey-service/))
server for Encedo Mail. Allows GPG, ProtonMail, Thunderbird and other OpenPGP-capable clients
to automatically discover and use public keys for recipients on your domain.

Part of the **Encedo Mail** project (Phase 1).

---

## Requirements

- Python 3.10+ (stdlib only — no pip, no external packages)

---

## Install

Run as **root** on the Carbonio server:

```bash
# 1. Clone the repository
git clone https://github.com/encedo/encedo-wkd
cd encedo-wkd

# 2. Install service, nginx extensions, systemd unit
sudo ./install.sh

# 3. Generate nginx config + TLS certs for openpgpkey.* domains
#    (reads domain list from Carbonio via zmprov, requests Let's Encrypt certs,
#     writes nginx WKD server blocks, generates config.json, reloads nginx)
sudo bash encedo-wkd-nginx-inject.sh

# 4. Start the service
sudo systemctl start encedo-wkd
sudo systemctl status encedo-wkd

# 5. Smoke test
curl https://openpgpkey.<your-domain>/.well-known/openpgpkey/policy
```

> **Note:** `encedo-wkd-nginx-inject.sh` must be run with `bash` (or `chmod +x` first) —
> it uses `bash`-specific syntax (`set -euo pipefail`, process substitution).
> Re-run it after adding a new domain or after a Carbonio upgrade.

### Update existing installation

```bash
cd encedo-wkd
git pull
sudo ./install.sh          # updates Python files + nginx extensions + reloads nginx
sudo systemctl restart encedo-wkd
```

---

## Configuration (config.json)

| Field         | Required | Default                    | Description                                          |
|---------------|----------|----------------------------|------------------------------------------------------|
| `port`        | yes      | —                          | Listening port (e.g. `8089`)                         |
| `host`        | no       | `127.0.0.1`                | Bind address                                         |
| `cache_dir`   | yes      | —                          | Key storage directory                                |
| `log_file`    | no       | `/var/log/encedo-wkd.log`  | Log file path                                        |
| `log_level`   | no       | `INFO`                     | Logging verbosity (`DEBUG`, `INFO`, `WARNING`)       |
| `carbonio_url`| no       | `""` (disabled)            | Carbonio internal URL for token validation — set to `http://127.0.0.1:8080` on Carbonio server; leave empty for standalone/local mode (no auth) |

Path to config file is set via `WKD_CONFIG` env var (default: `/opt/encedo-wkd/config.json`).

**Production example** (Carbonio server):
```json
{
  "port": 8089,
  "host": "127.0.0.1",
  "cache_dir": "/var/encedo-wkd/cache",
  "log_file": "/var/log/encedo-wkd.log",
  "log_level": "INFO",
  "carbonio_url": "http://127.0.0.1:8080"
}
```

**Standalone / local test** (no auth):
```json
{
  "port": 8089,
  "host": "127.0.0.1",
  "cache_dir": "/var/encedo-wkd/cache",
  "carbonio_url": ""
}
```

---

## nginx setup

`install.sh` automatically deploys two files to `/opt/zextras/conf/nginx/extensions/`
and reloads nginx — no manual steps needed:

| File | Purpose |
|------|---------|
| `upstream-wkd.conf` | upstream `wkd_server` → `127.0.0.1:8089` |
| `backend-wkd.conf` | `location /wkd/` proxy inside main Carbonio `server{}` block |

This exposes the publish/revoke API at `https://<carbonio-domain>/wkd/api/...`.

The `openpgpkey.*` virtual hosts (for WKD public key lookup) are generated separately
by `encedo-wkd-nginx-inject.sh`.

---

## API

### Authentication modes

**With Carbonio** (`carbonio_url` set in `config.json`):
- `X-Auth-Token` header required — Carbonio session token
- `server.py` validates the token against Carbonio SOAP `GetInfoRequest` (internal `http://127.0.0.1:8080`)
- Token email must match the `email` field in the request body
- Intended for production use via nginx proxy (`https://<carbonio-domain>/wkd/api/...`)

**Standalone / local** (`carbonio_url` empty or absent in `config.json`):
- No `X-Auth-Token` required
- Any email can be published/revoked — no ownership check
- Direct access to `http://127.0.0.1:8089` only (port not exposed externally)
- Intended for testing and standalone deployments

### Generate a GPG key (if you don't have one yet)

```bash
gpg --batch --gen-key <<EOF
Key-Type: EdDSA
Key-Curve: ed25519
Subkey-Type: ECDH
Subkey-Curve: cv25519
Name-Real: Jan Kowalski
Name-Email: jan@firma.pl
Expire-Date: 2y
%no-protection
EOF
```

### Publish a key

```bash
# Standalone / local (no auth):
gpg --export jan@firma.pl | base64 -w0 > /tmp/pubkey.b64
curl -s -X POST http://127.0.0.1:8089/api/publish \
  -H "Content-Type: application/json" \
  -d "{\"email\":\"jan@firma.pl\",\"pubkey_base64\":\"$(cat /tmp/pubkey.b64)\"}"
# Expected: {"ok": true, "hash": "<wkd_hash>"}

# Production via Carbonio proxy (requires X-Auth-Token):
TOKEN=<carbonio_session_token>
curl -s -X POST https://mailserver.encedo.com/wkd/api/publish \
  -H "Content-Type: application/json" \
  -H "X-Auth-Token: $TOKEN" \
  -d "{\"email\":\"jan@firma.pl\",\"pubkey_base64\":\"$(cat /tmp/pubkey.b64)\"}"
```

### Verify key was published

```bash
# WKD lookup — advanced method
curl -s "https://openpgpkey.firma.pl/.well-known/openpgpkey/firma.pl/hu/<hash>?l=jan" | wc -c

# Or via GPG
gpg --locate-key jan@firma.pl

# Online tester: https://wkd.chimbosonic.com
```

### Revoke a key

```bash
# Standalone / local (no auth):
curl -s -X DELETE http://127.0.0.1:8089/api/revoke \
  -H "Content-Type: application/json" \
  -d '{"email":"jan@firma.pl"}'
# Expected: {"ok": true}
# After revoke, WKD lookup returns 404.

# Production via Carbonio proxy:
curl -s -X DELETE https://mailserver.encedo.com/wkd/api/revoke \
  -H "Content-Type: application/json" \
  -H "X-Auth-Token: $TOKEN" \
  -d '{"email":"jan@firma.pl"}'
```

---

## Rollback

```bash
systemctl stop encedo-wkd
systemctl disable encedo-wkd
# nginx: remove the location block added for this service
```
