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

| Field     | Required | Default                  | Description        |
|-----------|----------|--------------------------|--> --------------------|
| port      | yes      | —                        | Listening port     |
| cache_dir | yes      | —                        | Key storage root   |
| host      | no       | 127.0.0.1                | Bind address       |
| log_file  | no       | /var/log/encedo-wkd.log  | Log file path      |
| log_level | no       | INFO                     | Logging verbosity  |

Path to config file is set via `WKD_CONFIG` env var (default: `/opt/encedo-wkd/config.json`).

---

## nginx setup

See `nginx/wkd.conf` for ready-to-paste snippets.
Add them to your nginx config — **never modify existing Carbonio blocks**.

---

## API

### Publish a key
```bash
gpg --export jan@firma.pl | base64 -w0 > /tmp/pubkey.b64

curl -X POST http://localhost:8089/api/publish \
  -H "Content-Type: application/json" \
  -d "{\"email\":\"jan@firma.pl\",\"pubkey_base64\":\"$(cat /tmp/pubkey.b64)\"}"
```

### Revoke a key
```bash
curl -X DELETE http://localhost:8089/api/revoke \
  -H "Content-Type: application/json" \
  -d '{"email":"jan@firma.pl"}'
```

### WKD lookup (manual test)
```bash
# Direct method
curl -v "https://firma.pl/.well-known/openpgpkey/hu/<hash>?l=jan"

# Advanced method
curl -v "https://openpgpkey.firma.pl/.well-known/openpgpkey/firma.pl/hu/<hash>?l=jan"

# GPG
gpg --locate-key jan@firma.pl

# Online tester
# https://wkd.chimbosonic.com
```

---

## Rollback

```bash
systemctl stop encedo-wkd
systemctl disable encedo-wkd
# nginx: remove the location block added for this service
```
