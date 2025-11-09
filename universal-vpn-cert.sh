#!/bin/bash
# universal-vpn-cert-lightweight.sh
# Lightweight Auto SSL/TLS certificate installer for VPN services
# Supports optional Cloudflare API, Stunnel5, Nginx, Webmin auto-reload, backup, logging
# By ChatGPT

set -euo pipefail

###########################
# CONFIGURATION
###########################
ACME_HOME="$HOME/.acme.sh"
STUNNEL_CERT="/etc/xray/xray.crt"
STUNNEL_KEY="/etc/xray/xray.key"
NGINX_CERT="/etc/ssl/universal-vpn/fullchain.cer"
NGINX_KEY="/etc/ssl/universal-vpn/private.key"
WEBMIN_CERT="/etc/ssl/webmin/miniserv.pem"
WEBMIN_KEY="/etc/ssl/webmin/miniserv.key"
LOG_DIR="/var/log/universal-vpn-cert"
BACKUP_DIR_BASE="/root/backup-cert"
MAX_LOG_DAYS=7

mkdir -p "$LOG_DIR"
mkdir -p "$(dirname "$NGINX_CERT")"
mkdir -p "$BACKUP_DIR_BASE"

TIMESTAMP=$(date '+%Y%m%d-%H%M%S')
LOG_FILE="$LOG_DIR/universal-vpn-cert-$TIMESTAMP.log"
exec > >(tee -a "$LOG_FILE") 2>&1

echo "===== Universal VPN Certificate Installer (Lightweight) ====="
echo "Timestamp: $TIMESTAMP"

###########################
# USER INPUT
###########################
echo "เลือกโหมดการใช้งาน:"
echo "1) ไม่ใช้ Cloudflare"
echo "2) ใช้ Cloudflare + Global API"
read -rp "กรุณาเลือก 1 หรือ 2: " MODE

read -rp "Enter your main domain (e.g., home.xq-vpn.com): " DOMAIN

if [[ "$MODE" == "2" ]]; then
    read -rp "Enter your Cloudflare Email: " CF_EMAIL
    read -rp "Enter your Cloudflare Global API Key: " CF_KEY
fi

###########################
# BACKUP EXISTING CERTS
###########################
BACKUP_DIR="$BACKUP_DIR_BASE/$TIMESTAMP"
mkdir -p "$BACKUP_DIR"

for FILE in "$STUNNEL_CERT" "$STUNNEL_KEY" "$NGINX_CERT" "$NGINX_KEY" "$WEBMIN_CERT" "$WEBMIN_KEY"; do
    if [ -f "$FILE" ]; then
        echo "[INFO] Backing up $FILE to $BACKUP_DIR"
        cp "$FILE" "$BACKUP_DIR/"
    fi
done

###########################
# CLEAN OLD LOGS
###########################
find "$LOG_DIR" -type f -mtime +$MAX_LOG_DAYS -name "*.log" -exec rm -f {} \;
echo "[INFO] Old logs older than $MAX_LOG_DAYS days removed."

###########################
# SET DEFAULT CA
###########################
"$ACME_HOME"/acme.sh --set-default-ca --server letsencrypt

###########################
# REMOVE OLD CERTS
###########################
if [ -d "$ACME_HOME/${DOMAIN}_ecc" ]; then
    echo "[INFO] Removing old certificate from acme.sh..."
    "$ACME_HOME"/acme.sh --remove -d "$DOMAIN" -d "*.$DOMAIN"
fi

###########################
# ISSUE WILDCARD CERTIFICATE
###########################
echo "[INFO] Issuing Let's Encrypt ECC wildcard certificate for $DOMAIN..."
if [[ "$MODE" == "2" ]]; then
    export CF_Email="$CF_EMAIL"
    export CF_Key="$CF_KEY"
fi

RETRY_COUNT=0
MAX_RETRIES=3
while [ $RETRY_COUNT -lt $MAX_RETRIES ]; do
    if [[ "$MODE" == "1" ]]; then
        if "$ACME_HOME"/acme.sh --issue -d "$DOMAIN" -d "*.$DOMAIN" --standalone --keylength ec-256 --force; then
            echo "[INFO] Certificate issued successfully."
            break
        fi
    else
        if "$ACME_HOME"/acme.sh --issue -d "$DOMAIN" -d "*.$DOMAIN" --dns dns_cf --keylength ec-256 --force; then
            echo "[INFO] Certificate issued successfully."
            break
        fi
    fi
    echo "[WARN] Certificate issuance failed. Retrying in 15s..."
    sleep 15
    RETRY_COUNT=$((RETRY_COUNT+1))
done

if [ $RETRY_COUNT -eq $MAX_RETRIES ]; then
    echo "[ERROR] Failed to issue certificate after $MAX_RETRIES attempts."
    exit 1
fi

###########################
# INSTALL CERTIFICATES
###########################
echo "[INFO] Installing certificate for stunnel5..."
"$ACME_HOME"/acme.sh --install-cert -d "$DOMAIN" \
    --ecc \
    --key-file "$STUNNEL_KEY" \
    --fullchain-file "$STUNNEL_CERT" \
    --reloadcmd "systemctl restart stunnel5 || echo '[WARN] Failed to restart stunnel5'"

echo "[INFO] Installing certificate for Nginx..."
"$ACME_HOME"/acme.sh --install-cert -d "$DOMAIN" \
    --ecc \
    --key-file "$NGINX_KEY" \
    --fullchain-file "$NGINX_CERT" \
    --reloadcmd "systemctl reload nginx || echo '[WARN] Failed to reload nginx'"

if [ -f "$WEBMIN_CERT" ] && [ -f "$WEBMIN_KEY" ]; then
    echo "[INFO] Installing certificate for Webmin..."
    "$ACME_HOME"/acme.sh --install-cert -d "$DOMAIN" \
        --ecc \
        --key-file "$WEBMIN_KEY" \
        --fullchain-file "$WEBMIN_CERT" \
        --reloadcmd "systemctl restart webmin || echo '[WARN] Failed to restart webmin'"
fi

###########################
# SET PERMISSIONS
###########################
chmod 600 "$STUNNEL_KEY" "$STUNNEL_CERT" "$NGINX_KEY" "$NGINX_CERT"
chown root:root "$STUNNEL_KEY" "$STUNNEL_CERT" "$NGINX_KEY" "$NGINX_CERT"

if [ -f "$WEBMIN_KEY" ]; then
    chmod 600 "$WEBMIN_KEY" "$WEBMIN_CERT"
    chown root:root "$WEBMIN_KEY" "$WEBMIN_CERT"
fi

###########################
# SUCCESS
###########################
echo "===== Success! ====="
echo "Certificates installed:"
echo "Stunnel5 Key  : $STUNNEL_KEY"
echo "Stunnel5 Cert : $STUNNEL_CERT"
echo "Nginx Key     : $NGINX_KEY"
echo "Nginx Cert    : $NGINX_CERT"
if [ -f "$WEBMIN_KEY" ]; then
    echo "Webmin Key    : $WEBMIN_KEY"
    echo "Webmin Cert   : $WEBMIN_CERT"
fi
echo "Wildcard domain ready: *.$DOMAIN"
echo "Backup of previous certs in: $BACKUP_DIR"
echo "Log file: $LOG_FILE"
echo "Certificates will auto-renew via acme.sh cron."

###########################
# SYSTEMD PATH UNIT FOR AUTO SSL RELOAD
###########################
AUTO_SSL_SCRIPT="/usr/local/bin/universal-vpn-auto-ssl.sh"

cat << 'EOF' > "$AUTO_SSL_SCRIPT"
#!/bin/bash
STUNNEL_CERT="/etc/xray/xray.crt"
STUNNEL_KEY="/etc/xray/xray.key"
NGINX_CERT="/etc/ssl/universal-vpn/fullchain.cer"
NGINX_KEY="/etc/ssl/universal-vpn/private.key"
WEBMIN_CERT="/etc/ssl/webmin/miniserv.pem"
WEBMIN_KEY="/etc/ssl/webmin/miniserv.key"

reload_service() {
    local service=$1
    if systemctl is-active --quiet "$service"; then
        systemctl restart "$service" && echo "[INFO] $service reloaded" || echo "[WARN] Failed to reload $service"
    fi
}

if [[ -f "$STUNNEL_CERT" && -f "$STUNNEL_KEY" ]]; then
    reload_service "stunnel5"
fi

if [[ -f "$NGINX_CERT" && -f "$NGINX_KEY" ]]; then
    reload_service "nginx"
fi

if [[ -f "$WEBMIN_CERT" && -f "$WEBMIN_KEY" ]]; then
    reload_service "webmin"
fi
EOF

chmod +x "$AUTO_SSL_SCRIPT"

cat << EOF > /etc/systemd/system/universal-vpn-auto-ssl.path
[Unit]
Description=Watch universal-vpn-cert SSL files and reload services

[Path]
PathModified=/etc/xray/xray.crt
PathModified=/etc/xray/xray.key
PathModified=/etc/ssl/universal-vpn/fullchain.cer
PathModified=/etc/ssl/universal-vpn/private.key
PathModified=/etc/ssl/webmin/miniserv.pem
PathModified=/etc/ssl/webmin/miniserv.key

[Install]
WantedBy=multi-user.target
EOF

cat << EOF > /etc/systemd/system/universal-vpn-auto-ssl.service
[Unit]
Description=Reload VPN/NGINX/Webmin SSL when certificate changes

[Service]
Type=oneshot
ExecStart=$AUTO_SSL_SCRIPT
EOF

systemctl daemon-reload
systemctl enable --now universal-vpn-auto-ssl.path

echo "[INFO] Systemd path unit for auto SSL reload enabled."

exit 0
