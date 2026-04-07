#!/bin/bash
# encedo-wkd-nginx-inject.sh
# Generates nginx config for WKD (openpgpkey.*) based on domains from Carbonio.
#
# Integrates with Carbonio's certbot (/opt/zextras/common/bin/certbot)
# Certificates stored in: /opt/zextras/common/certbot/etc/letsencrypt/live/
#
# Run:
#   - after first installation
#   - after adding a new domain to Carbonio
#   - after Carbonio upgrade (nginx.conf.web.https gets cleared)
#   - after running your cert renewal script
#
# Requirements:
#   - Carbonio certbot installed
#   - CNAME openpgpkey.domain.tld -> mailserver.encedo.com in client DNS
#   - encedo-wkd running on 127.0.0.1:8089

set -euo pipefail

# ---------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------
TARGET="/opt/zextras/conf/nginx/includes/nginx.conf.web.https"
WEBROOT="/opt/zextras/common/certbot/etc/letsencrypt/webroot"
CERTBOT_BIN="/opt/zextras/common/bin/certbot"
CERTBOT_ROOT="/opt/zextras/common/certbot/etc/letsencrypt"
ADMIN_EMAIL="admin@encedo.com"
WKD_PORT="8089"
NGINX_BIN="/opt/zextras/common/sbin/nginx"
NGINX_CONF="/opt/zextras/conf/nginx.conf"
NGINX_DEFAULT_HTTPS="/opt/zextras/conf/nginx/includes/nginx.conf.web.https.default"

# ---------------------------------------------------------------
# Check privileges
# ---------------------------------------------------------------
if [ "$(whoami)" != "root" ]; then
    echo "ERROR: must be run as root (sudo)"
    exit 1
fi

mkdir -p "$WEBROOT"

# ---------------------------------------------------------------
# Get domain list from Carbonio
# ---------------------------------------------------------------
echo ">>> Fetching domain list from Carbonio..."
DOMAINS=$(su - zextras -c "zmprov gad")

if [ -z "$DOMAINS" ]; then
    echo "ERROR: No domains found or zmprov failed"
    exit 1
fi

echo ">>> Domains found:"
echo "$DOMAINS" | sed 's/^/    /'

# ---------------------------------------------------------------
# Per domain: check DNS and generate cert if missing
# ---------------------------------------------------------------
echo ""
echo ">>> Checking DNS and certificates..."

ACTIVE_DOMAINS=""
CERTS_TO_REQUEST=""

for DOMAIN in $DOMAINS; do
    SUBDOMAIN="openpgpkey.${DOMAIN}"
    CERTPATH="${CERTBOT_ROOT}/live/${SUBDOMAIN}/fullchain.pem"

    # Check if CNAME resolves
    RESOLVED=$(dig +short "$SUBDOMAIN" 2>/dev/null | tail -1)
    if [ -z "$RESOLVED" ]; then
        echo "SKIP: $SUBDOMAIN -- no CNAME in DNS, skipping"
        continue
    fi
    echo "DNS:  $SUBDOMAIN -> $RESOLVED"

    # Check if cert exists
    if [ -f "$CERTPATH" ]; then
        EXPIRY=$(openssl x509 -enddate -noout -in "$CERTPATH" 2>/dev/null | cut -d= -f2)
        echo "CERT: $SUBDOMAIN -- cert exists (expires: $EXPIRY)"
        ACTIVE_DOMAINS="$ACTIVE_DOMAINS $DOMAIN"
    else
        echo "MARK: $SUBDOMAIN -- will request cert"
        CERTS_TO_REQUEST="$CERTS_TO_REQUEST $SUBDOMAIN"
    fi
done

# ---------------------------------------------------------------
# Generate missing certificates (if any)
# ---------------------------------------------------------------
if [ -n "$CERTS_TO_REQUEST" ]; then
    echo ""
    echo ">>> Stopping Carbonio for certificate generation..."
    su - zextras -c "zmcontrol stop"
    
    for SUBDOMAIN in $CERTS_TO_REQUEST; do
        echo ">>> Requesting Let's Encrypt cert for $SUBDOMAIN..."
        "$CERTBOT_BIN" certonly \
            --standalone \
            --non-interactive \
            --agree-tos \
            --email "$ADMIN_EMAIL" \
            -d "$SUBDOMAIN" \
            --quiet

        if [ $? -eq 0 ]; then
            echo "OK:   $SUBDOMAIN -- cert generated"
            DOMAIN=$(echo "$SUBDOMAIN" | sed 's/openpgpkey\.//')
            ACTIVE_DOMAINS="$ACTIVE_DOMAINS $DOMAIN"
        else
            echo "FAIL: $SUBDOMAIN -- certbot failed, skipping"
        fi
    done
    
    echo ">>> Restarting Carbonio..."
    su - zextras -c "zmcontrol start"
    
    echo ">>> Fixing certificate permissions for nginx..."
    for SUBDOMAIN in $CERTS_TO_REQUEST; do
        PRIVKEY_PATH="${CERTBOT_ROOT}/live/${SUBDOMAIN}/privkey.pem"
        if [ -f "$PRIVKEY_PATH" ]; then
            chmod 644 "$PRIVKEY_PATH"
            chown root:zextras "$PRIVKEY_PATH" 2>/dev/null || true
            echo "OK:   $SUBDOMAIN -- privkey permissions fixed"
        fi
    done
fi

# ---------------------------------------------------------------
# Check if anything is active
# ---------------------------------------------------------------
if [ -z "$ACTIVE_DOMAINS" ]; then
    echo ""
    echo "WARNING: No domains with valid cert and DNS"
    echo "         Check CNAME openpgpkey.* in client DNS"
    exit 1
fi

# ---------------------------------------------------------------
# Detect Carbonio nginx IP (must match Carbonio's default_server socket)
# ---------------------------------------------------------------
# Carbonio binds to a specific IP (e.g. 65.21.170.222:443 default_server).
# Our server blocks must listen on the same IP:port socket, otherwise
# nginx will never route SNI-based connections to our blocks.
NGINX_IP=$(grep "listen.*443 default_server" "$NGINX_DEFAULT_HTTPS" 2>/dev/null \
    | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | head -1)

if [ -z "$NGINX_IP" ]; then
    echo "WARNING: Could not detect Carbonio nginx IP from $NGINX_DEFAULT_HTTPS"
    echo "         Falling back to 0.0.0.0 (listen 443) -- SNI may not work"
    NGINX_LISTEN_443="443 ssl"
    NGINX_LISTEN_80="80"
else
    echo ">>> Detected Carbonio nginx IP: $NGINX_IP"
    NGINX_LISTEN_443="${NGINX_IP}:443 ssl"
    NGINX_LISTEN_80="${NGINX_IP}:80"
fi

# ---------------------------------------------------------------
# Generate nginx config
# ---------------------------------------------------------------
# ---------------------------------------------------------------
# Start nginx first so Carbonio template regeneration happens
# before we write our config (zmproxyctl regenerates from templates)
# ---------------------------------------------------------------
echo ">>> Starting nginx (template regeneration pass)..."
su - zextras -c "zmproxyctl restart"

echo ""
echo ">>> Generating nginx config: $TARGET"

cat > "$TARGET" << NGINX_HEADER
# encedo-wkd -- nginx config for WKD (openpgpkey.*)
# Auto-generated by: /usr/local/bin/encedo-wkd-nginx-inject.sh
# DO NOT EDIT MANUALLY -- changes will be overwritten
# Generated: $(date)

# ---------------------------------------------------------------
# Port 80 -- Let's Encrypt webroot + redirect for openpgpkey.*
# ---------------------------------------------------------------
server {
    listen ${NGINX_LISTEN_80};
    server_name ~^openpgpkey\..+\$;

    location /.well-known/acme-challenge/ {
        root ${WEBROOT};
    }

    location / {
        return 301 https://\$host\$request_uri;
    }
}

NGINX_HEADER

# Server block per domain
COUNT=0
for DOMAIN in $ACTIVE_DOMAINS; do
    SUBDOMAIN="openpgpkey.${DOMAIN}"
    CERTPATH="${CERTBOT_ROOT}/live/${SUBDOMAIN}"

    cat >> "$TARGET" << NGINX_BLOCK
# ---------------------------------------------------------------
# WKD: ${DOMAIN}
# ---------------------------------------------------------------
server {
    listen ${NGINX_LISTEN_443};
    server_name ${SUBDOMAIN};

    ssl_protocols           TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers on;
    ssl_session_cache       shared:SSL:10m;
    ssl_session_timeout     600;
    ssl_certificate         ${CERTPATH}/fullchain.pem;
    ssl_certificate_key     ${CERTPATH}/privkey.pem;

    location /.well-known/openpgpkey {
        proxy_pass          http://127.0.0.1:${WKD_PORT};
        proxy_http_version  1.1;
        proxy_set_header    Host              \$host;
        proxy_set_header    X-Forwarded-Host  \$host;
        proxy_set_header    X-Real-IP         \$remote_addr;
        proxy_set_header    X-Forwarded-Proto \$scheme;
    }

    # All other requests -> custom error page
    location / {
        return 404;
    }

    error_page 404 /wkd-error.html;
    location = /wkd-error.html {
        root /var/www/encedo-wkd;
        internal;
    }
}

NGINX_BLOCK

    COUNT=$((COUNT + 1))
    echo "OK:   $SUBDOMAIN -- added to nginx config"
done

chown zextras:zextras "$TARGET"

# ---------------------------------------------------------------
# Generate custom error page
# ---------------------------------------------------------------
echo ""
echo ">>> Generating custom error page..."
mkdir -p /var/www/encedo-wkd

cat > /var/www/encedo-wkd/wkd-error.html << 'HTML'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Encedo WKD</title>
    <style>
        body {
            font-family: monospace;
            background: #0a0c0f;
            color: #888;
            display: flex;
            align-items: center;
            justify-content: center;
            height: 100vh;
            margin: 0;
        }
        .box {
            text-align: center;
        }
        .logo {
            color: #7C35F0;
            font-size: 1.4em;
            font-weight: bold;
            margin-bottom: 1em;
            letter-spacing: 0.1em;
        }
        .title {
            color: #ccc;
            font-size: 1em;
            margin-bottom: 0.5em;
        }
        .desc {
            font-size: 0.8em;
            color: #555;
            margin-bottom: 1.5em;
        }
        a {
            color: #7C35F0;
            text-decoration: none;
            font-size: 0.8em;
        }
        a:hover { text-decoration: underline; }
    </style>
</head>
<body>
    <div class="box">
        <div class="logo">ENCEDO WKD</div>
        <div class="title">Web Key Directory</div>
        <div class="desc">This host serves OpenPGP public keys only.<br>
        No content is available at this address.</div>
        <a href="https://www.encedo.com">encedo.com</a>
    </div>
</body>
</html>
HTML

echo "OK:   /var/www/encedo-wkd/wkd-error.html generated"

# ---------------------------------------------------------------
# Generate config.json
# ---------------------------------------------------------------
echo ""
echo ">>> Generating config.json..."

WKD_CONFIG_DIR="/opt/encedo-wkd"
WKD_CONFIG="${WKD_CONFIG_DIR}/config.json"
WKD_CACHE_DIR="/var/encedo-wkd/cache"
WKD_LOG_FILE="/var/log/encedo-wkd.log"
WKD_LOG_LEVEL="INFO"
# Create directories
mkdir -p "$WKD_CONFIG_DIR"
mkdir -p "$WKD_CACHE_DIR"

# Generate JSON config
cat > "$WKD_CONFIG" << JSON_CONFIG
{
  "port": ${WKD_PORT},
  "host": "127.0.0.1",
  "cache_dir": "${WKD_CACHE_DIR}",
  "log_file": "${WKD_LOG_FILE}",
  "log_level": "${WKD_LOG_LEVEL}",
  "carbonio_url": "http://127.0.0.1:8080"
}
JSON_CONFIG

# Validate JSON syntax
if ! python3 -m json.tool "$WKD_CONFIG" > /dev/null 2>&1; then
    echo "ERROR: Generated config.json has invalid JSON syntax"
    rm -f "$WKD_CONFIG"
    exit 1
fi

# Set ownership and permissions
chown www-data:www-data "$WKD_CONFIG"
chmod 0600 "$WKD_CONFIG"

# Set cache directory permissions
chown www-data:www-data "$WKD_CACHE_DIR"
chmod 0755 "$WKD_CACHE_DIR"

echo "OK:   $WKD_CONFIG generated"
echo "OK:   Cache directory: $WKD_CACHE_DIR"

echo ""
echo ">>> Testing nginx config..."
su - zextras -c "$NGINX_BIN -t -c $NGINX_CONF"
if [ $? -ne 0 ]; then
    echo "ERROR: nginx config invalid -- reverting"
    > "$TARGET"
    chown zextras:zextras "$TARGET"
    exit 1
fi

# ---------------------------------------------------------------
# Reload nginx (direct reload -- no template regeneration)
# ---------------------------------------------------------------
echo ">>> Reloading nginx (nginx -s reload)..."
su - zextras -c "$NGINX_BIN -s reload -c $NGINX_CONF"

# nginx workers run as 'nobody' and may reset ownership of temp dirs.
# Restore correct ownership so Carbonio proxy buffering keeps working.
chown -R zextras:zextras /opt/zextras/data/tmp/nginx/

# ---------------------------------------------------------------
# Summary
# ---------------------------------------------------------------
echo ""
echo "-----------------------------------------------"
echo "  encedo-wkd -- DEPLOYMENT COMPLETE"
echo "-----------------------------------------------"
echo ""
echo "  Configuration:"
echo "  + config.json:    $WKD_CONFIG"
echo "  + cache_dir:      $WKD_CACHE_DIR"
echo "  + log_file:       $WKD_LOG_FILE"
echo "  + port:           $WKD_PORT"
echo ""
echo "  Active WKD domains ($COUNT):"
for DOMAIN in $ACTIVE_DOMAINS; do
    echo "  + openpgpkey.${DOMAIN}"
done
echo ""
echo "  Quick test:"
FIRST_DOMAIN=$(echo "$ACTIVE_DOMAINS" | awk '{print $1}')
echo "  $ curl https://openpgpkey.${FIRST_DOMAIN}/.well-known/openpgpkey/policy"
echo ""
echo "  Next: Start encedo-wkd service"
echo "  $ sudo systemctl start encedo-wkd"
echo ""
echo "  Re-run this script after:"
echo "    - Carbonio upgrade"
echo "    - adding a new domain"
echo "    - cert renewal (your cert renewal script)"
echo "-----------------------------------------------"
