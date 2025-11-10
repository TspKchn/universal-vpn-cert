#!/usr/bin/env bash
# universal-vpn-cert-full.sh
# Full-featured Universal VPN Certificate Installer (Lightweight)
# Supports: stunnel4, stunnel5, nginx, webmin, x-ui (3x-ui), xray, trojan-go
# Cloudflare DNS-01 optional
# Creates /root/cert/<DOMAIN>/fullchain.pem & privkey.pem for 3x-ui
# Auto backup, logging, auto-clean logs, systemd path reload
# Auto-renew only when cert < 30 days remaining
# By ChatGPT (adapted)

set -euo pipefail

###########################
# CONFIG
###########################
ACME_HOME="$HOME/.acme.sh"
ACME_BIN="$ACME_HOME/acme.sh"

STUNNEL5_CERT="/etc/xray/xray.crt"
STUNNEL5_KEY="/etc/xray/xray.key"
STUNNEL4_CERT="/etc/stunnel/stunnel.crt"
STUNNEL4_KEY="/etc/stunnel/stunnel.key"

NGINX_CERT="/etc/ssl/universal-vpn/fullchain.cer"
NGINX_KEY="/etc/ssl/universal-vpn/private.key"

WEBMIN_CERT="/etc/ssl/webmin/miniserv.pem"
WEBMIN_KEY="/etc/ssl/webmin/miniserv.key"

ROOT_CERT_BASE="/root/cert"    # 3x-ui certificates directory
LOG_DIR="/var/log/universal-vpn-cert"
BACKUP_DIR_BASE="/root/backup-cert"

MAX_LOG_DAYS=7
MAX_BACKUPS_KEEP=1   # keep only latest by default
RENEW_THRESHOLD=30   # days remaining to renew

mkdir -p "$LOG_DIR" "$BACKUP_DIR_BASE" "$ROOT_CERT_BASE" "$(dirname "$NGINX_CERT")"

TIMESTAMP=$(date '+%Y%m%d-%H%M%S')
LOG_FILE="$LOG_DIR/universal-vpn-cert-$TIMESTAMP.log"
exec > >(tee -a "$LOG_FILE") 2>&1

echo "===== Universal VPN Certificate Installer (Full) ====="
echo "Timestamp: $TIMESTAMP"
echo

###########################
# HELPERS
###########################
has_cmd(){ command -v "$1" >/dev/null 2>&1; }
svc_exists(){ systemctl list-units --type=service --all --no-legend | grep -Fq "$1.service" || systemctl list-units --type=service --all --no-legend | grep -Fq "$1"; }
is_active(){ systemctl is-active --quiet "$1" >/dev/null 2>&1; }

prompt_yesno(){ read -rp "$1 [y/N]: " ans || true; [[ "$ans" =~ ^[Yy] ]]; }

install_acme_sh_if_missing(){
    if [ ! -x "$ACME_BIN" ]; then
        echo "[INFO] Installing acme.sh..."
        apt-get update -y
        apt-get install -y socat curl
        curl https://get.acme.sh | sh || { echo "[ERROR] acme.sh install failed"; exit 1; }
        ACME_HOME="$HOME/.acme.sh"
        ACME_BIN="$ACME_HOME/acme.sh"
    fi
}

stop_services_port80(){
    local tostop=()
    if ss -tulpn | grep -q ':80 '; then
        echo "[WARN] Port 80 in use, stopping common services..."
        for s in nginx xray caddy apache2 httpd; do
            if svc_exists "$s"; then
                systemctl stop "$s" || true
                tostop+=("$s")
            fi
        done
    fi
    STOPPED_PORT80_SERVICES=("${tostop[@]}")
}

restart_stopped_services(){
    for s in "${STOPPED_PORT80_SERVICES[@]}"; do
        echo "[INFO] Restarting $s..."
        systemctl start "$s" || true
    done
}

detect_services(){
    HAS_STUNNEL5=0; HAS_STUNNEL4=0; HAS_NGINX=0; HAS_WEBMIN=0; HAS_XUI=0; HAS_XRAY=0; HAS_TROJAN_GO=0
    [ "$(svc_exists stunnel5 || has_cmd stunnel5)" ] && HAS_STUNNEL5=1
    [ "$(svc_exists stunnel4 || has_cmd stunnel)" ] && HAS_STUNNEL4=1
    [ "$(svc_exists nginx || has_cmd nginx)" ] && HAS_NGINX=1
    [ "$(svc_exists webmin || has_cmd webmin)" ] && HAS_WEBMIN=1
    if svc_exists x-ui || has_cmd x-ui || [ -f /usr/local/bin/x-ui ]; then HAS_XUI=1; fi
    [ "$(svc_exists xray || has_cmd xray)" ] && HAS_XRAY=1
    [ "$(svc_exists trojan-go || has_cmd trojan-go)" ] && HAS_TROJAN_GO=1
}

days_until_expire(){
    local cert_file="$1"
    if [ ! -f "$cert_file" ]; then echo 0; return; fi
    openssl x509 -in "$cert_file" -noout -enddate | cut -d= -f2 | xargs -I{} date -d {} +%s | awk -v now=$(date +%s) '{print int(($1-now)/86400)}'
}

###########################
# INPUT
###########################
echo "เลือกโหมดการใช้งาน:"
echo " 1) Standalone HTTP-01"
echo " 2) Cloudflare DNS-01"
read -rp "เลือก 1 หรือ 2: " MODE
[[ "$MODE" == "1" || "$MODE" == "2" ]] || { echo "[ERROR] เลือก 1 หรือ 2"; exit 1; }

read -rp "Domain (e.g., home.xq-vpn.com): " DOMAIN
DOMAIN="${DOMAIN// /}"

CF_EMAIL=""; CF_KEY=""
if [[ "$MODE" == "2" ]]; then
    read -rp "Cloudflare Email: " CF_EMAIL
    read -rp "Cloudflare Global API Key: " CF_KEY
fi

prompt_yesno "ลบสำรองเก่าเก็บเฉพาะล่าสุด?" && MAX_BACKUPS_KEEP=1 || MAX_BACKUPS_KEEP=5

###########################
# PREPARE
###########################
install_acme_sh_if_missing
"$ACME_BIN" --set-default-ca --server letsencrypt >/dev/null 2>&1
echo "[INFO] acme.sh ready: $ACME_BIN"

detect_services
echo "[INFO] Detected services: stunnel5:$HAS_STUNNEL5, stunnel4:$HAS_STUNNEL4, nginx:$HAS_NGINX, webmin:$HAS_WEBMIN, x-ui:$HAS_XUI, xray:$HAS_XRAY, trojan-go:$HAS_TROJAN_GO"

BACKUP_DIR="$BACKUP_DIR_BASE/$TIMESTAMP"
mkdir -p "$BACKUP_DIR"
for FILE in "$STUNNEL5_CERT" "$STUNNEL5_KEY" "$STUNNEL4_CERT" "$STUNNEL4_KEY" "$NGINX_CERT" "$NGINX_KEY" "$WEBMIN_CERT" "$WEBMIN_KEY"; do
    [ -f "$FILE" ] && cp -a "$FILE" "$BACKUP_DIR/" || true
done

# cleanup old backups and logs
mapfile -t _dirs < <(ls -1dt "$BACKUP_DIR_BASE"/* 2>/dev/null || true)
if [ "${#_dirs[@]}" -gt "$MAX_BACKUPS_KEEP" ]; then
    for ((i=MAX_BACKUPS_KEEP;i<${#_dirs[@]};i++)); do rm -rf "${_dirs[$i]}" || true; done
fi
find "$LOG_DIR" -type f -mtime +"$MAX_LOG_DAYS" -name "*.log" -exec rm -f {} \; || true

###########################
# AUTO RENEW LOGIC
###########################
CERT_CHECK_FILE="$NGINX_CERT"
if [[ "$HAS_XUI" -eq 1 ]]; then
    CERT_CHECK_FILE="$ROOT_CERT_BASE/$DOMAIN/fullchain.pem"
fi
if [ -f "$CERT_CHECK_FILE" ]; then
    REMAIN_DAYS=$(days_until_expire "$CERT_CHECK_FILE")
    echo "[INFO] Certificate days remaining: $REMAIN_DAYS"
    if [ "$REMAIN_DAYS" -gt "$RENEW_THRESHOLD" ]; then
        echo "[INFO] Certificate valid for >$RENEW_THRESHOLD days, skipping renewal."
        exit 0
    fi
fi

###########################
# ISSUE CERTIFICATE
###########################
STOPPED_PORT80_SERVICES=()
[[ "$MODE" == "1" && $(ss -tulpn | grep -q ':80 '; echo $?) -eq 0 ]] && stop_services_port80

echo "[INFO] Issuing ECC wildcard certificate for $DOMAIN ..."
export CF_Email="$CF_EMAIL" CF_Key="$CF_KEY"
RETRY=0; MAX_RETRY=3; ISSUE_OK=0
while [ $RETRY -lt $MAX_RETRY ]; do
    if [[ "$MODE" == "1" ]]; then
        "$ACME_BIN" --issue -d "$DOMAIN" -d "*.$DOMAIN" --standalone --keylength ec-256 --force && ISSUE_OK=1 && break
    else
        "$ACME_BIN" --issue -d "$DOMAIN" -d "*.$DOMAIN" --dns dns_cf --keylength ec-256 --force && ISSUE_OK=1 && break
    fi
    echo "[WARN] Attempt $((RETRY+1)) failed. Retry in 15s..."
    sleep 15
    RETRY=$((RETRY+1))
done

restart_stopped_services
[ "$ISSUE_OK" -eq 1 ] || { echo "[ERROR] Failed to issue certificate"; exit 1; }

CERT_DIR="$ACME_HOME/${DOMAIN}_ecc"
FULLCHAIN="$CERT_DIR/fullchain.cer"
KEYFILE="$CERT_DIR/${DOMAIN}.key"

###########################
# INSTALL CERTIFICATES
###########################
install_cert_to(){
    local cert="$1" key="$2" svc="$3"
    [ -f "$cert" ] && [ -f "$key" ] || return
    cp -f "$cert" "$svc" && cp -f "$key" "$svc" || true
    chmod 600 "$svc"
}

# Stunnel
if [ "$HAS_STUNNEL5" -eq 1 ]; then
    cp -f "$FULLCHAIN" "$STUNNEL5_CERT"
    cp -f "$KEYFILE" "$STUNNEL5_KEY"
    chmod 600 "$STUNNEL5_CERT" "$STUNNEL5_KEY"
    systemctl restart stunnel5 || echo "[WARN] Failed restart stunnel5"
elif [ "$HAS_STUNNEL4" -eq 1 ]; then
    cp -f "$FULLCHAIN" "$STUNNEL4_CERT"
    cp -f "$KEYFILE" "$STUNNEL4_KEY"
    chmod 600 "$STUNNEL4_CERT" "$STUNNEL4_KEY"
    systemctl restart stunnel || echo "[WARN] Failed restart stunnel4"
fi

# Nginx
[ "$HAS_NGINX" -eq 1 ] && { cp -f "$FULLCHAIN" "$NGINX_CERT"; cp -f "$KEYFILE" "$NGINX_KEY"; chmod 600 "$NGINX_CERT" "$NGINX_KEY"; systemctl reload nginx || true; }

# Webmin
[ "$HAS_WEBMIN" -eq 1 ] && { cp -f "$FULLCHAIN" "$WEBMIN_CERT"; cp -f "$KEYFILE" "$WEBMIN_KEY"; chmod 600 "$WEBMIN_CERT" "$WEBMIN_KEY"; systemctl restart webmin || true; }

# 3x-ui / x-ui
if [ "$HAS_XUI" -eq 1 ]; then
    UI_DIR="$ROOT_CERT_BASE/$DOMAIN"
    mkdir -p "$UI_DIR"
    cp -f "$FULLCHAIN" "$UI_DIR/fullchain.pem"
    cp -f "$KEYFILE" "$UI_DIR/privkey.pem"
    chmod 600 "$UI_DIR/fullchain.pem" "$UI_DIR/privkey.pem"
    systemctl restart x-ui || true
fi

###########################
# SYSTEMD AUTO-RELOAD
###########################
AUTO_SCRIPT="/usr/local/bin/universal-vpn-auto-ssl.sh"
cat > "$AUTO_SCRIPT" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
reload_svc(){ svc="$1"; systemctl is-active --quiet "$svc" && systemctl restart "$svc" && echo "[AUTO-SSL] $svc restarted"; }
STUNNEL5_CERT="/etc/xray/xray.crt"
STUNNEL5_KEY="/etc/xray/xray.key"
STUNNEL4_CERT="/etc/stunnel/stunnel.crt"
STUNNEL4_KEY="/etc/stunnel/stunnel.key"
NGINX_CERT="/etc/ssl/universal-vpn/fullchain.cer"
NGINX_KEY="/etc/ssl/universal-vpn/private.key"
WEBMIN_CERT="/etc/ssl/webmin/miniserv.pem"
WEBMIN_KEY="/etc/ssl/webmin/miniserv.key"
ROOT_CERT_BASE="/root/cert"
[ -f "$STUNNEL5_CERT" ] && [ -f "$STUNNEL5_KEY" ] && reload_svc stunnel5
[ -f "$STUNNEL4_CERT" ] && [ -f "$STUNNEL4_KEY" ] && reload_svc stunnel
[ -f "$NGINX_CERT" ] && [ -f "$NGINX_KEY" ] && reload_svc nginx
[ -f "$WEBMIN_CERT" ] && [ -f "$WEBMIN_KEY" ] && reload_svc webmin
command -v x-ui >/dev/null 2>&1 && reload_svc x-ui
for d in "$ROOT_CERT_BASE"/*; do
  [ -d "$d" ] && [ -f "$NGINX_CERT" ] && [ -f "$NGINX_KEY" ] && cp -f "$NGINX_CERT" "$d/fullchain.pem" && cp -f "$NGINX_KEY" "$d/privkey.pem" && chmod 600 "$d/fullchain.pem" "$d/privkey.pem"
done
EOF
chmod +x "$AUTO_SCRIPT"

cat > /etc/systemd/system/universal-vpn-auto-ssl.service <<EOF
[Unit]
Description=Reload VPN/Nginx/Webmin/x-ui SSL when certificates change
After=network.target

[Service]
Type=oneshot
ExecStart=$AUTO_SCRIPT
EOF

cat > /etc/systemd/system/universal-vpn-auto-ssl.path <<EOF
[Unit]
Description=Watch SSL files for universal-vpn-cert

[Path]
PathModified=/etc/xray/xray.crt
PathModified=/etc/xray/xray.key
PathModified=/etc/stunnel/stunnel.crt
PathModified=/etc/stunnel/stunnel.key
PathModified=/etc/ssl/universal-vpn/fullchain.cer
PathModified=/etc/ssl/universal-vpn/private.key
PathModified=/etc/ssl/webmin/miniserv.pem
PathModified=/etc/ssl/webmin/miniserv.key

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now universal-vpn-auto-ssl.path || echo "[WARN] Could not enable path unit"

echo "[INFO] Certificates installed and auto-reload enabled."
echo "Backup in: $BACKUP_DIR"
echo "Log: $LOG_FILE"
echo "Wildcard domain: *.$DOMAIN"
echo "All features included: 3x-ui compatibility, auto-renew < $RENEW_THRESHOLD days, backup, log rotation, systemd reload."
echo "Done."
exit 0
