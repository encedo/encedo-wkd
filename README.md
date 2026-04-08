# encedo-wkd

WKD (Web Key Directory, [RFC draft](https://datatracker.ietf.org/doc/draft-koch-openpgp-webkey-service/))
server for Encedo Mail. Allows GPG, ProtonMail, Thunderbird and other OpenPGP-capable clients
to automatically discover and use public keys for recipients on your domain.

Part of **Encedo Mail**. See [ARCH.md](../ARCH.md) for full system architecture.

---

## Requirements

- Python 3.10+ (stdlib only — no pip, no external packages)
- nginx (Carbonio's nginx on production)

---

## Install

Run as **root** on the Carbonio server:

```bash
sudo ./install.sh
sudo bash encedo-wkd-nginx-inject.sh   # generates nginx config + TLS certs
sudo systemctl start encedo-wkd
```

Re-run `encedo-wkd-nginx-inject.sh` after adding a new domain or after a Carbonio upgrade.

### Update

```bash
git pull
sudo ./install.sh
sudo systemctl restart encedo-wkd
```

---

## Configuration (config.json)

| Field | Required | Default | Description |
|-------|----------|---------|-------------|
| `port` | yes | — | Listening port (8089) |
| `host` | no | `127.0.0.1` | Bind address |
| `cache_dir` | yes | — | Key storage directory |
| `log_file` | no | `/var/log/encedo-wkd.log` | Log file |
| `log_level` | no | `INFO` | Verbosity |
| `auth_backend` | no | auto | `"carbonio"` or `"none"` (auto-detected from `carbonio_url`) |
| `carbonio_url` | no | `""` | Required when `auth_backend=carbonio`. Set to `http://127.0.0.1:8080` in production. |

Config path via `WKD_CONFIG` env var (default: `/opt/encedo-wkd/config.json`).

### Auth backends

| Backend | When to use |
|---------|-------------|
| `carbonio` | Integrated with Carbonio/Zextras mail server — validates session tokens via SOAP |
| `none` | Standalone / local-only — port not exposed externally, keys managed via `wkd-cli` |

To implement a custom backend (e.g. LDAP, Keycloak): subclass `AuthBackend` in `auth/` and register it in `auth/__init__.py:load_backend()`.

---

## API

### Authentication

**Production** (`auth_backend=carbonio`):
- `X-Auth-Token` header required (Carbonio session token)
- Token validated against Carbonio SOAP `GetInfoRequest`
- Also accepted from `Cookie: ZM_AUTH_TOKEN=...` (ZM_AUTH_TOKEN is HttpOnly — JS can't read it)
- Token email must match the `email` field or one of the account's aliases

**Standalone** (`auth_backend=none`): no auth required. Port 8089 not exposed externally.

### CLI (no server required)

```bash
# Publish a key directly (admin, local)
python3 wkd_cli.py publish --email jan@firma.pl --key /path/to/pub.asc

# Revoke
python3 wkd_cli.py revoke --email jan@firma.pl

# List all keys
python3 wkd_cli.py list [--domain firma.pl]

# Show key details
python3 wkd_cli.py show --email jan@firma.pl

# Print WKD hash for an email
python3 wkd_cli.py hash --email jan@firma.pl
```

### Publish a key

```bash
gpg --export jan@firma.pl | base64 -w0 > /tmp/pubkey.b64

# Production (via Carbonio proxy):
curl -X POST https://mailserver.encedo.com/wkd/api/publish \
  -H "Content-Type: application/json" \
  -H "X-Auth-Token: $TOKEN" \
  -d "{\"email\":\"jan@firma.pl\",\"pubkey_base64\":\"$(cat /tmp/pubkey.b64)\"}"

# Standalone / local:
curl -X POST http://127.0.0.1:8089/api/publish \
  -H "Content-Type: application/json" \
  -d "{\"email\":\"jan@firma.pl\",\"pubkey_base64\":\"$(cat /tmp/pubkey.b64)\"}"
```

Server validates that the submitted key contains a User ID matching the requested email.

### Revoke a key

```bash
curl -X DELETE https://mailserver.encedo.com/wkd/api/revoke \
  -H "Content-Type: application/json" \
  -H "X-Auth-Token: $TOKEN" \
  -d '{"email":"jan@firma.pl"}'
```

### Verify key is published

```bash
# Via GPG (tries advanced then direct method):
gpg --locate-key jan@firma.pl

# Via curl:
HASH=$(python3 -c "from wkd import wkd_hash; print(wkd_hash('jan'))")
curl "https://openpgpkey.firma.pl/.well-known/openpgpkey/firma.pl/hu/${HASH}?l=jan" | wc -c
```

---

## nginx setup

`install.sh` deploys nginx extension files to `/opt/zextras/conf/nginx/extensions/`:

| File | Purpose |
|------|---------|
| `upstream-wkd.conf` | upstream `wkd_server` → `127.0.0.1:8089` |
| `backend-wkd.conf` | `location /wkd/` proxy inside main Carbonio `server{}` block |

`encedo-wkd-nginx-inject.sh` generates `openpgpkey.*` virtual hosts with Let's Encrypt certs.
Uses `listen <IP>:443` (specific IP, not `*:443`) to share the socket with Carbonio's `default_server`.
