#!/usr/bin/env bash
# universal-vpn-cert.sh
# Universal lightweight auto SSL installer (Full-featured, but lightweight)
set -euo pipefail

########################
# Config
########################
ACME_HOME="$HOME/.acme.sh"
ACME_BIN="$ACME_HOME/acme.sh"
STUNNEL_CERT="/etc/xray/xray.crt"
STUNNEL_KEY="/etc/xray/xray.key"
NGINX_CERT="/etc/ssl/universal-vpn/fullchain.cer"
NGINX_KEY="/etc/ssl/universal-vpn/private.key"
WEBMIN_CERT="/etc/ssl/webmin/miniserv.pem"
WEBMIN_KEY="/etc/ssl/webmin/miniserv.key"
ROOT_CERT_BASE="/root/cert"
LOG_DIR="/var/log/universal-vpn-cert"
BACKUP_DIR_BASE="/root/backup-cert"
MAX_LOG_DAYS=7
MAX_BACKUPS_KEEP=1

mkdir -p "$LOG_DIR" "$BACKUP_DIR_BASE" "$ROOT_CERT_BASE" "$(dirname "$NGINX_CERT")"

TIMESTAMP="$(date '+%Y%m%d-%H%M%S')"
LOG_FILE="$LOG_DIR/universal-vpn-cert-$TIMESTAMP.log"
exec > >(tee -a "$LOG_FILE") 2>&1

echo "===== Universal VPN Certificate Installer (Lightweight) ====="
echo "Timestamp: $TIMESTAMP"
echo

########################
# Helpers
########################
has_cmd(){ command -v "$1" >/dev/null 2>&1; }
svc_exists(){ systemctl list-units --type=service --all --no-legend | grep -Fq "$1.service" || systemctl list-units --type=service --all --no-legend | grep -Fq "$1"; }
stop_services_using_port80_temporarily() {
    local tostop=()
    if ss -tulpn | grep -q ':80 '; then
        echo "[WARN] Port 80 is in use. Trying to stop common services temporarily..."
        for s in nginx xray caddy apache2 httpd; do
            if svc_exists "$s"; then
                echo "[INFO] Stopping $s temporarily..."
                systemctl stop "$s" || true
                tostop+=("$s")
            fi
        done
    fi
    STOPPED_PORT80_SERVICES=("${tostop[@]}")
}
restart_services_stopped_for_port80() {
    for s in "${STOPPED_PORT80_SERVICES[@]}"; do
        echo "[INFO] Starting previously stopped service: $s"
        systemctl start "$s" || true
    done
}
days_until_expire() {
    local cert_file="$1"
    if [ ! -f "$cert_file" ]; then echo 0; return; fi
    local end_epoch=$(date -d "$(openssl x509 -enddate -noout -in "$cert_file" | cut -d= -f2)" +%s)
    local now_epoch=$(date +%s)
    echo $(( (end_epoch - now_epoch) / 86400 ))
}
install_acme_sh_if_missing() {
    if [ ! -x "$ACME_BIN" ]; then
        echo "[INFO] acme.sh not found. Installing..."
        apt-get update -y
        apt-get install -y socat curl
        curl https://get.acme.sh | sh || { echo "[ERROR] acme.sh install failed"; exit 1; }
        ACME_HOME="$HOME/.acme.sh"
        ACME_BIN="$ACME_HOME/acme.sh"
        [ -x "$ACME_BIN" ] || { echo "[ERROR] acme.sh not executable"; exit 1; }
    fi
}

########################
# Input
########################
echo "เลือกโหมดการใช้งาน:"
echo "  1) ไม่ใช้ Cloudflare (standalone HTTP-01)"
echo "  2) ใช้ Cloudflare (DNS-01)"
read -rp "กรุณาเลือก 1 หรือ 2: " MODE
[[ "$MODE" == "1" || "$MODE" == "2" ]] || { echo "[ERROR] เลือก 1 หรือ 2"; exit 1; }

read -rp "Enter your main domain (e.g., home.xq-vpn.com): " DOMAIN
DOMAIN="${DOMAIN// /}"

CF_EMAIL=""; CF_KEY=""
[[ "$MODE" == "2" ]] && read -rp "Enter Cloudflare Email: " CF_EMAIL && read -rp "Enter Cloudflare Global API Key: " CF_KEY

read -rp "ลบสำรองเก่าเก็บเฉพาะล่าสุด? (y/N): " keep_choice || true
[[ "$keep_choice" =~ ^[Yy] ]] && MAX_BACKUPS_KEEP=1 || MAX_BACKUPS_KEEP=5

echo "[INFO] domain: $DOMAIN"
[[ "$MODE" == "2" ]] && echo "[INFO] Cloudflare mode ON"

########################
# Determine cert paths (Step 1)
########################
CERT_DIR="$ACME_HOME/${DOMAIN}_ecc"
CERT_FILE="$CERT_DIR/${DOMAIN}.cer"
KEY_FILE="$CERT_DIR/${DOMAIN}.key"
FULLCHAIN="$CERT_DIR/fullchain.cer"
CA_CER="$CERT_DIR/ca.cer"

########################
# Prepare
########################
detect_services() {
    SERVICES=()
    for s in stunnel5 stunnel4 nginx webmin x-ui x-ui.service x-ui-panel x-ui-daemon x-ui-manager 3x-ui xray trojan-go; do
        svc_exists "$s" && SERVICES+=("$s")
    done
    HAS_STUNNEL5=0; HAS_STUNNEL4=0; HAS_NGINX=0; HAS_WEBMIN=0; HAS_XUI=0; HAS_XRAY=0; HAS_TROJAN_GO=0
    [[ " ${SERVICES[*]} " =~ stunnel5 ]] && HAS_STUNNEL5=1
    [[ " ${SERVICES[*]} " =~ stunnel4 ]] && HAS_STUNNEL4=1
    [[ " ${SERVICES[*]} " =~ nginx ]] && HAS_NGINX=1
    [[ " ${SERVICES[*]} " =~ webmin ]] && HAS_WEBMIN=1
    [[ " ${SERVICES[*]} " =~ x-ui ]] && HAS_XUI=1
    [[ " ${SERVICES[*]} " =~ xray ]] && HAS_XRAY=1
    [[ " ${SERVICES[*]} " =~ trojan-go ]] && HAS_TROJAN_GO=1
}
install_cert_for_services() {
    echo "[INFO] Installing certificates..."
    [[ "$HAS_STUNNEL5" -eq 1 || "$HAS_STUNNEL4" -eq 1 ]] && { cp -f "$FULLCHAIN" "$STUNNEL_CERT"; cp -f "$KEY_FILE" "$STUNNEL_KEY"; chmod 600 "$STUNNEL_CERT" "$STUNNEL_KEY"; chown root:root "$STUNNEL_CERT" "$STUNNEL_KEY"; svc_exists stunnel5 && systemctl restart stunnel5 || svc_exists stunnel4 && systemctl restart stunnel || true; }
    [[ "$HAS_NGINX" -eq 1 ]] && { mkdir -p "$(dirname "$NGINX_CERT")"; cp -f "$FULLCHAIN" "$NGINX_CERT"; cp -f "$KEY_FILE" "$NGINX_KEY"; chmod 600 "$NGINX_CERT" "$NGINX_KEY"; chown root:root "$NGINX_CERT" "$NGINX_KEY"; systemctl reload nginx || true; }
    [[ "$HAS_WEBMIN" -eq 1 ]] && { cp -f "$FULLCHAIN" "$WEBMIN_CERT"; cp -f "$KEY_FILE" "$WEBMIN_KEY"; chmod 600 "$WEBMIN_CERT" "$WEBMIN_KEY"; chown root:root "$WEBMIN_CERT" "$WEBMIN_KEY"; systemctl restart webmin || true; }
    [[ "$HAS_XUI" -eq 1 ]] && { UI_CERT_DIR="$ROOT_CERT_BASE/$DOMAIN"; mkdir -p "$UI_CERT_DIR"; cp -f "$FULLCHAIN" "$UI_CERT_DIR/fullchain.pem"; cp -f "$KEY_FILE" "$UI_CERT_DIR/privkey.pem"; chmod 600 "$UI_CERT_DIR/fullchain.pem" "$UI_CERT_DIR/privkey.pem"; chown root:root "$UI_CERT_DIR/fullchain.pem" "$UI_CERT_DIR/privkey.pem"; svc_exists x-ui && systemctl restart x-ui || true; }
    [[ "$HAS_XRAY" -eq 1 ]] && { cp -f "$FULLCHAIN" "/etc/xray/xray.crt"; cp -f "$KEY_FILE" "/etc/xray/xray.key"; chmod 600 "/etc/xray/xray.crt" "/etc/xray/xray.key"; systemctl restart xray || true; }
    [[ "$HAS_TROJAN_GO" -eq 1 ]] && { cp -f "$FULLCHAIN" "/etc/trojan-go/trojan-go.crt"; cp -f "$KEY_FILE" "/etc/trojan-go/trojan-go.key"; chmod 600 "/etc/trojan-go/trojan-go.crt" "/etc/trojan-go/trojan-go.key"; systemctl restart trojan-go || true; }
}

detect_services

BACKUP_DIR="$BACKUP_DIR_BASE/$TIMESTAMP"
mkdir -p "$BACKUP_DIR"
for FILE in "$STUNNEL_CERT" "$STUNNEL_KEY" "$NGINX_CERT" "$NGINX_KEY" "$WEBMIN_CERT" "$WEBMIN_KEY"; do
    [ -f "$FILE" ] && cp -a "$FILE" "$BACKUP_DIR/" || true
done

# rotate backups
mapfile -t _dirs < <(ls -1dt "$BACKUP_DIR_BASE"/* 2>/dev/null || true)
for ((i=MAX_BACKUPS_KEEP;i<${#_dirs[@]};i++)); do rm -rf "${_dirs[$i]}" || true; done
find "$LOG_DIR" -type f -mtime +"$MAX_LOG_DAYS" -name "*.log" -exec rm -f {} \; || true

install_acme_sh_if_missing
"$ACME_BIN" --set-default-ca --server letsencrypt >/dev/null 2>&1

# Stop services if standalone and port 80 in use
STOPPED_PORT80_SERVICES=()
[[ "$MODE" == "1" ]] && ss -tulpn | grep -q ':80 ' && stop_services_using_port80_temporarily

# -------------------------
# Skip renewal if cert still valid >30 days
# -------------------------
MAX_DAYS_LEFT=30
ISSUE_OK=0
if [ -f "$FULLCHAIN" ]; then
    days_left=$(days_until_expire "$FULLCHAIN")
    echo "[INFO] Certificate for $DOMAIN expires in $days_left days"
    if [ "$days_left" -gt "$MAX_DAYS_LEFT" ]; then
        echo "[INFO] Certificate still valid >$MAX_DAYS_LEFT days. Skip renewal."
        ISSUE_OK=1
        install_cert_for_services
    fi
fi

########################
# Issue certificate (wildcard)
########################
if [ "$ISSUE_OK" -ne 1 ]; then
    echo "[INFO] Issuing Let's Encrypt ECC wildcard certificate for $DOMAIN ..."
    [[ "$MODE" == "2" ]] && export CF_Email="$CF_EMAIL" && export CF_Key="$CF_KEY"

    RETRY=0; MAX_RETRY=3
    while [ $RETRY -lt $MAX_RETRY ]; do
        if [[ "$MODE" == "1" ]]; then
            "$ACME_BIN" --issue -d "$DOMAIN" -d "*.$DOMAIN" --standalone --keylength ec-256 --force && ISSUE_OK=1 && break
        else
            "$ACME_BIN" --issue -d "$DOMAIN" -d "*.$DOMAIN" --dns dns_cf --keylength ec-256 --force && ISSUE_OK=1 && break
        fi
        echo "[WARN] attempt $((RETRY+1)) failed — retrying in 15s..."
        sleep 15
        RETRY=$((RETRY+1))
    done
fi

# backup old cert if renewal
[ -f "$FULLCHAIN" ] && [ "$ISSUE_OK" -ne 1 ] && cp -a "$FULLCHAIN" "$BACKUP_DIR/" && cp -a "$KEY_FILE" "$BACKUP_DIR/"

# restart stopped services
[ "${#STOPPED_PORT80_SERVICES[@]}" -gt 0 ] && restart_services_stopped_for_port80

# install newly issued certs
[ "$ISSUE_OK" -eq 1 ] && install_cert_for_services

# validate
[ "$ISSUE_OK" -ne 1 ] && { echo "[ERROR] Failed to issue certificate"; exit 1; }
[ ! -f "$FULLCHAIN" ] || [ ! -f "$KEY_FILE" ] && { echo "[ERROR] expected cert files not found in $CERT_DIR"; exit 1; }

echo "===== Success! ====="
########################
# systemd path watcher: reload services when cert files change
########################
AUTO_SSL_SCRIPT="/usr/local/bin/universal-vpn-auto-ssl.sh"
cat > "$AUTO_SSL_SCRIPT" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

STUNNEL_CERT="/etc/xray/xray.crt"
STUNNEL_KEY="/etc/xray/xray.key"
NGINX_CERT="/etc/ssl/universal-vpn/fullchain.cer"
NGINX_KEY="/etc/ssl/universal-vpn/private.key"
WEBMIN_CERT="/etc/ssl/webmin/miniserv.pem"
WEBMIN_KEY="/etc/ssl/webmin/miniserv.key"
ROOT_CERT_BASE="/root/cert"

reload_if_active() {
    local svc="$1"
    systemctl is-active --quiet "$svc" && systemctl restart "$svc" && echo "[AUTO-SSL] restarted $svc" || echo "[AUTO-SSL] failed to restart $svc"
}

# Reload services if certs exist
[[ -f "$STUNNEL_CERT" && -f "$STUNNEL_KEY" ]] && { reload_if_active "stunnel5" || reload_if_active "stunnel"; }
[[ -f "$NGINX_CERT" && -f "$NGINX_KEY" ]] && reload_if_active "nginx"
[[ -f "$WEBMIN_CERT" && -f "$WEBMIN_KEY" ]] && reload_if_active "webmin"
command -v x-ui >/dev/null 2>&1 && reload_if_active "x-ui"

# Update domain folders in /root/cert for 3x-ui/x-ui
if [ -d "$ROOT_CERT_BASE" ]; then
    for d in "$ROOT_CERT_BASE"/*; do
        [ -d "$d" ] || continue
        [[ -f "$NGINX_CERT" && -f "$NGINX_KEY" ]] && cp -f "$NGINX_CERT" "$d/fullchain.pem" && cp -f "$NGINX_KEY" "$d/privkey.pem" && chmod 600 "$d/fullchain.pem" "$d/privkey.pem"
    done
fi
EOF

chmod +x "$AUTO_SSL_SCRIPT"

# systemd path unit (watch commonly used cert files)
cat > /etc/systemd/system/universal-vpn-auto-ssl.path <<EOF
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

# systemd service unit
cat > /etc/systemd/system/universal-vpn-auto-ssl.service <<EOF
[Unit]
Description=Reload services on certificate change
After=network.target

[Service]
Type=oneshot
ExecStart=$AUTO_SSL_SCRIPT
EOF

systemctl daemon-reload
systemctl enable --now universal-vpn-auto-ssl.path || echo "[WARN] Could not enable universal-vpn-auto-ssl.path"
echo "[INFO] Systemd path unit for auto SSL reload enabled."

########################
# Final summary
########################
echo
echo "Wildcard domain ready: *.$DOMAIN"
echo "Backup of previous certs in: $BACKUP_DIR"
echo "Log file: $LOG_FILE"
echo "Certificates will auto-renew via acme.sh cron."
echo "[INFO] Done."
exit 0
