#!/bin/bash
# encedo-wkd install.sh
# Installs encedo-wkd on a Carbonio server.
#
# Run as root:
#   sudo ./install.sh
#
# After install:
#   1. sudo ./encedo-wkd-nginx-inject.sh   (generates certs, nginx config, config.json)
#   2. systemctl start encedo-wkd

set -e

WKD_DIR="/opt/encedo-wkd"
NGINX_EXT="/opt/zextras/conf/nginx/extensions"
SYSTEMD_DIR="/etc/systemd/system"
LOG_FILE="/var/log/encedo-wkd.log"
CACHE_DIR="/var/encedo-wkd/cache"

if [ "$(id -u)" -ne 0 ]; then
    echo "ERROR: run as root (sudo ./install.sh)"
    exit 1
fi

echo "[1/6] Creating directories..."
mkdir -p "$WKD_DIR"
mkdir -p "$CACHE_DIR"
cp ./*.py "$WKD_DIR/"
cp -r auth "$WKD_DIR/"

echo "[2/6] Installing config.json (if not present)..."
if [ ! -f "$WKD_DIR/config.json" ]; then
    cp config.json.example "$WKD_DIR/config.json"
    echo "      -> Fill in $WKD_DIR/config.json before starting the service!"
else
    echo "      -> config.json already exists, skipping."
fi

echo "[3/6] Setting permissions..."
chown -R www-data:www-data "$WKD_DIR"
chmod 750 "$WKD_DIR"
chmod 640 "$WKD_DIR/config.json"
chmod 644 "$WKD_DIR"/*.py
find "$WKD_DIR/auth" -name "*.py" -exec chmod 644 {} \;
chown -R www-data:www-data "$CACHE_DIR"
chmod 755 "$CACHE_DIR"

echo "[4/6] Installing nginx extensions..."
mkdir -p "$NGINX_EXT"
cp nginx/upstream-wkd.conf "$NGINX_EXT/"
cp nginx/backend-wkd.conf  "$NGINX_EXT/"
chown zextras:zextras "$NGINX_EXT/upstream-wkd.conf" "$NGINX_EXT/backend-wkd.conf"

echo "[5/6] Installing systemd service..."
cp encedo-wkd.service "$SYSTEMD_DIR/"
systemctl daemon-reload
systemctl enable encedo-wkd

echo "[6/6] Preparing log file and verifying nginx..."
touch "$LOG_FILE"
chown www-data:www-data "$LOG_FILE"
su - zextras -c "/opt/zextras/common/sbin/nginx -t" && \
    su - zextras -c "/opt/zextras/common/sbin/nginx -s reload" || \
    { echo "ERROR: nginx -t failed — check configuration!"; exit 1; }

echo ""
echo "=== Installation complete ==="
echo "1. Run: sudo ./encedo-wkd-nginx-inject.sh"
echo "   (generates TLS certs, nginx WKD config, config.json)"
echo "2. Edit $WKD_DIR/config.json — set carbonio_url if needed"
echo "3. systemctl start encedo-wkd"
echo "4. curl http://127.0.0.1:8089/.well-known/openpgpkey/policy"
