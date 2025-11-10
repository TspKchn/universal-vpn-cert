#!/usr/bin/env bash
# universal-vpn-cert.sh
# Universal lightweight auto SSL installer (Full-featured, but lightweight)
# Supports: stunnel4, stunnel5, nginx, webmin, x-ui (3x-ui), xray, trojan-go
# Cloudflare DNS optional
# By ChatGPT (adapted for user's environment)

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

mkdir -p "$LOG_DIR"
mkdir -p "$(dirname "$NGINX_CERT")"
mkdir -p "$BACKUP_DIR_BASE"
mkdir -p "$ROOT_CERT_BASE"

TIMESTAMP="$(date '+%Y%m%d-%H%M%S')"
LOG_FILE="$LOG_DIR/universal-vpn-cert-$TIMESTAMP.log"
exec > >(tee -a "$LOG_FILE") 2>&1

echo "===== Universal VPN Certificate Installer ====="
echo "Timestamp: $TIMESTAMP"
echo

########################
# Helpers
########################
has_cmd(){ command -v "$1" >/dev/null 2>&1; }
svc_exists(){ systemctl list-units --type=service --all --no-legend | grep -Fq "$1.service" || systemctl list-units --type=service --all --no-legend | grep -Fq "$1"; }
is_active(){ systemctl is-active --quiet "$1" >/dev/null 2>&1; }
port_in_use(){ ss -tulpn | awk '{print $5" "$7}' | grep -E ":[0-9]+$" | grep -q ":$1\b"; }

prompt_yesno() {
    local prompt="$1"; shift
    local default="${1:-n}"
    local ans
    read -rp "$prompt [y/N]: " ans || true
    case "$ans" in
        [Yy]*) return 0 ;;
        *) return 1 ;;
    esac
}

install_acme_sh_if_missing() {
    if [ ! -x "$ACME_BIN" ]; then
        echo "[INFO] acme.sh not found. Installing..."
        apt-get update -y
        apt-get install -y socat curl
        curl https://get.acme.sh | sh || { echo "[ERROR] acme.sh install failed"; exit 1; }
        ACME_HOME="$HOME/.acme.sh"
        ACME_BIN="$ACME_HOME/acme.sh"
        if [ ! -x "$ACME_BIN" ]; then
            echo "[ERROR] acme.sh not executable after install"
            exit 1
        fi
    fi
}

days_until_expire() {
    local cert_file="$1"
    if [ ! -f "$cert_file" ]; then
        echo 0
        return
    fi
    local end_date
    end_date=$(openssl x509 -enddate -noout -in "$cert_file" | cut -d= -f2)
    local end_epoch
    end_epoch=$(date -d "$end_date" +%s)
    local now_epoch
    now_epoch=$(date +%s)
    local days_left=$(( (end_epoch - now_epoch) / 86400 ))
    echo "$days_left"
}

stop_services_using_port80_temporarily() {
    local tostop=()
    if ss -tulpn | grep -q ':80 '; then
        echo "[WARN] Port 80 in use. Stopping common services..."
        for s in nginx xray caddy apache2 httpd; do
            if svc_exists "$s"; then
                echo "[INFO] Stopping $s..."
                systemctl stop "$s" || true
                tostop+=("$s")
            fi
        done
    fi
    STOPPED_PORT80_SERVICES=("${tostop[@]}")
}

restart_services_stopped_for_port80() {
    if [ "${#STOPPED_PORT80_SERVICES[@]}" -gt 0 ]; then
        for s in "${STOPPED_PORT80_SERVICES[@]}"; do
            echo "[INFO] Starting previously stopped service: $s"
            systemctl start "$s" || true
        done
    fi
}

detect_services() {
    SERVICES=()
    for s in stunnel5 stunnel4 nginx webmin x-ui 3x-ui xray trojan-go; do
        if svc_exists "$s" || has_cmd "$s"; then
            SERVICES+=("$s")
        fi
    done

    HAS_STUNNEL5=0; HAS_STUNNEL4=0; HAS_NGINX=0; HAS_WEBMIN=0; HAS_XUI=0; HAS_XRAY=0; HAS_TROJAN_GO=0
    if svc_exists stunnel5 || has_cmd stunnel5; then HAS_STUNNEL5=1; fi
    if svc_exists stunnel4 || has_cmd stunnel; then HAS_STUNNEL4=1; fi
    if svc_exists nginx || has_cmd nginx; then HAS_NGINX=1; fi
    if svc_exists webmin || has_cmd webmin; then HAS_WEBMIN=1; fi
    if svc_exists x-ui || has_cmd x-ui; then HAS_XUI=1; fi
    if svc_exists xray || has_cmd xray; then HAS_XRAY=1; fi
    if svc_exists trojan-go || has_cmd trojan-go; then HAS_TROJAN_GO=1; fi
}

########################
# Input from user
########################
echo "เลือกโหมดการใช้งาน:"
echo "  1) ไม่ใช้ Cloudflare (standalone HTTP-01)"
echo "  2) ใช้ Cloudflare (DNS-01)"
read -rp "กรุณาเลือก 1 หรือ 2: " MODE
if [[ "$MODE" != "1" && "$MODE" != "2" ]]; then
    echo "[ERROR] กรุณาเลือก 1 หรือ 2"
    exit 1
fi

read -rp "Enter your main domain (e.g., test.xq-vpn.com): " DOMAIN
DOMAIN="${DOMAIN// /}"  # trim spaces

# -------------------------
# determine acme paths for ECC
CERT_DIR="$ACME_HOME/${DOMAIN}_ecc"
CERT_FILE="$CERT_DIR/${DOMAIN}.cer"
KEY_FILE="$CERT_DIR/${DOMAIN}.key"
FULLCHAIN="$CERT_DIR/fullchain.cer"
CA_CER="$CERT_DIR/ca.cer"

CF_EMAIL=""; CF_KEY=""
if [[ "$MODE" == "2" ]]; then
    read -rp "Enter your Cloudflare Email: " CF_EMAIL
    read -rp "Enter your Cloudflare Global API Key: " CF_KEY
fi

read -rp "ลบสำรองเก่าเก็บเฉพาะล่าสุด? (y/N): " keep_choice || true
if [[ "$keep_choice" =~ ^[Yy] ]]; then
    MAX_BACKUPS_KEEP=1
else
    MAX_BACKUPS_KEEP=5
fi

echo "[INFO] domain: $DOMAIN"
if [[ "$MODE" == "2" ]]; then
    echo "[INFO] Cloudflare mode ON"
fi

detect_services
echo "[INFO] Detected services:"
echo "  stunnel5: $HAS_STUNNEL5, stunnel4: $HAS_STUNNEL4, nginx: $HAS_NGINX, webmin: $HAS_WEBMIN, x-ui: $HAS_XUI, xray: $HAS_XRAY, trojan-go: $HAS_TROJAN_GO"

########################
# Backup old certs
########################
BACKUP_DIR="$BACKUP_DIR_BASE/$TIMESTAMP"
mkdir -p "$BACKUP_DIR"
for FILE in "$STUNNEL_CERT" "$STUNNEL_KEY" "$NGINX_CERT" "$NGINX_KEY" "$WEBMIN_CERT" "$WEBMIN_KEY"; do
    if [ -f "$FILE" ]; then
        echo "[INFO] Backing up $FILE to $BACKUP_DIR"
        cp -a "$FILE" "$BACKUP_DIR/" || true
    fi
done

# rotate backups
if [ -d "$BACKUP_DIR_BASE" ]; then
    mapfile -t _dirs < <(ls -1dt "$BACKUP_DIR_BASE"/* 2>/dev/null || true)
    if [ "${#_dirs[@]}" -gt "$MAX_BACKUPS_KEEP" ]; then
        for ((i=MAX_BACKUPS_KEEP;i<${#_dirs[@]};i++)); do
            rm -rf "${_dirs[$i]}" || true
        done
    fi
fi

# cleanup old logs
find "$LOG_DIR" -type f -mtime +"$MAX_LOG_DAYS" -name "*.log" -exec rm -f {} \; || true
echo "[INFO] Old logs older than $MAX_LOG_DAYS days removed."

# ensure acme.sh installed
install_acme_sh_if_missing
"$ACME_BIN" --set-default-ca --server letsencrypt >/dev/null 2>&1 || true
echo "[INFO] acme.sh ready: $ACME_BIN"

# Part 1/3 ends here (176 lines)

########################
# Stop services temporarily if standalone and port 80 in use
########################
STOPPED_PORT80_SERVICES=()
if [[ "$MODE" == "1" ]]; then
    if ss -tulpn | grep -q ':80 '; then
        stop_services_using_port80_temporarily
    fi
fi

########################
# Skip renewal if cert still valid >30 days
########################
MAX_DAYS_LEFT=30
ISSUE_OK=0
if [ -f "$FULLCHAIN" ]; then
    days_left=$(days_until_expire "$FULLCHAIN")
    echo "[INFO] Certificate for $DOMAIN expires in $days_left days"
    if [ "$days_left" -gt "$MAX_DAYS_LEFT" ]; then
        echo "[INFO] Certificate still valid >$MAX_DAYS_LEFT days. Skip renewal."
        ISSUE_OK=1
        # Install existing cert to all services
        install_cert_for_services() {
            # stunnel
            if [ "$HAS_STUNNEL5" -eq 1 ] || [ "$HAS_STUNNEL4" -eq 1 ]; then
                cp -f "$FULLCHAIN" "$STUNNEL_CERT"
                cp -f "$KEY_FILE" "$STUNNEL_KEY"
                chmod 600 "$STUNNEL_CERT" "$STUNNEL_KEY"
                chown root:root "$STUNNEL_CERT" "$STUNNEL_KEY"
                if svc_exists stunnel5; then systemctl restart stunnel5 || true
                elif svc_exists stunnel4; then systemctl restart stunnel || true; fi
            fi
            # nginx
            if [ "$HAS_NGINX" -eq 1 ]; then
                mkdir -p "$(dirname "$NGINX_CERT")"
                cp -f "$FULLCHAIN" "$NGINX_CERT"
                cp -f "$KEY_FILE" "$NGINX_KEY"
                chmod 600 "$NGINX_CERT" "$NGINX_KEY"
                chown root:root "$NGINX_CERT" "$NGINX_KEY"
                systemctl reload nginx || true
            fi
            # webmin
            if [ "$HAS_WEBMIN" -eq 1 ]; then
                mkdir -p "$(dirname "$WEBMIN_CERT")"
                cp -f "$FULLCHAIN" "$WEBMIN_CERT"
                cp -f "$KEY_FILE" "$WEBMIN_KEY"
                chmod 600 "$WEBMIN_CERT" "$WEBMIN_KEY"
                chown root:root "$WEBMIN_CERT" "$WEBMIN_KEY"
                systemctl restart webmin || true
            fi
            # x-ui / 3x-ui
            if [ "$HAS_XUI" -eq 1 ]; then
                UI_CERT_DIR="$ROOT_CERT_BASE/$DOMAIN"
                mkdir -p "$UI_CERT_DIR"
                cp -f "$FULLCHAIN" "$UI_CERT_DIR/fullchain.pem"
                cp -f "$KEY_FILE" "$UI_CERT_DIR/privkey.pem"
                chmod 600 "$UI_CERT_DIR/fullchain.pem" "$UI_CERT_DIR/privkey.pem"
                chown root:root "$UI_CERT_DIR/fullchain.pem" "$UI_CERT_DIR/privkey.pem"
                if svc_exists x-ui || has_cmd x-ui; then
                    systemctl restart x-ui || true
                fi
            fi
            # xray
            if [ "$HAS_XRAY" -eq 1 ]; then
                XRAY_CERT_DIR="/etc/xray"
                cp -f "$FULLCHAIN" "$XRAY_CERT_DIR/xray.crt"
                cp -f "$KEY_FILE" "$XRAY_CERT_DIR/xray.key"
                chmod 600 "$XRAY_CERT_DIR/xray.crt" "$XRAY_CERT_DIR/xray.key"
                systemctl restart xray || true
            fi
            # trojan-go
            if [ "$HAS_TROJAN_GO" -eq 1 ]; then
                TROJAN_CERT_DIR="/etc/trojan-go"
                cp -f "$FULLCHAIN" "$TROJAN_CERT_DIR/trojan-go.crt"
                cp -f "$KEY_FILE" "$TROJAN_CERT_DIR/trojan-go.key"
                chmod 600 "$TROJAN_CERT_DIR/trojan-go.crt" "$TROJAN_CERT_DIR/trojan-go.key"
                systemctl restart trojan-go || true
            fi
        }
        install_cert_for_services
    fi
fi

########################
# Issue certificate
########################
if [ "$ISSUE_OK" -ne 1 ]; then
    echo "[INFO] Issuing Let's Encrypt ECC wildcard certificate for $DOMAIN..."
    if [[ "$MODE" == "2" ]]; then
        export CF_Email="$CF_EMAIL"
        export CF_Key="$CF_KEY"
    fi

    RETRY=0
    MAX_RETRY=3
    while [ $RETRY -lt $MAX_RETRY ]; do
        if [[ "$MODE" == "1" ]]; then
            if "$ACME_BIN" --issue -d "$DOMAIN" -d "*.$DOMAIN" --standalone --keylength ec-256 --force; then
                ISSUE_OK=1; break
            fi
        else
            if "$ACME_BIN" --issue -d "$DOMAIN" -d "*.$DOMAIN" --dns dns_cf --keylength ec-256 --force; then
                ISSUE_OK=1; break
            fi
        fi
        echo "[WARN] attempt $((RETRY+1)) failed — retrying in 15s..."
        sleep 15
        RETRY=$((RETRY+1))
    done
fi

########################
# Backup current cert before renewal
########################
if [ -f "$FULLCHAIN" ] && [ "$ISSUE_OK" -ne 1 ]; then
    echo "[INFO] Backing up current cert before renewal..."
    cp -a "$FULLCHAIN" "$BACKUP_DIR/" || true
    cp -a "$KEY_FILE" "$BACKUP_DIR/" || true
fi

# Restart services stopped for port 80
if [[ "${#STOPPED_PORT80_SERVICES[@]}" -gt 0 ]]; then
    echo "[INFO] Restarting services previously stopped for port 80..."
    restart_services_stopped_for_port80
fi

########################
# Install certificates to services after issuance
########################
if [ "$ISSUE_OK" -eq 1 ]; then
    install_cert_for_services
fi

if [ "$ISSUE_OK" -ne 1 ]; then
    echo "[ERROR] Failed to issue certificate after $MAX_RETRY attempts."
    exit 1
fi

if [ ! -f "$FULLCHAIN" ] || [ ! -f "$KEY_FILE" ]; then
    echo "[ERROR] expected cert files not found in $CERT_DIR"
    exit 1
fi

########################
# Install certificates (redundant safety)
########################
# stunnel
if [ "$HAS_STUNNEL5" -eq 1 ] || [ "$HAS_STUNNEL4" -eq 1 ]; then
    cp -f "$FULLCHAIN" "$STUNNEL_CERT"
    cp -f "$KEY_FILE" "$STUNNEL_KEY"
    chmod 600 "$STUNNEL_CERT" "$STUNNEL_KEY"
    chown root:root "$STUNNEL_CERT" "$STUNNEL_KEY"
    if svc_exists stunnel5; then systemctl restart stunnel5 || true
    elif svc_exists stunnel4; then systemctl restart stunnel || true; fi
fi

# nginx
if [ "$HAS_NGINX" -eq 1 ]; then
    mkdir -p "$(dirname "$NGINX_CERT")"
    cp -f "$FULLCHAIN" "$NGINX_CERT"
    cp -f "$KEY_FILE" "$NGINX_KEY"
    chmod 600 "$NGINX_CERT" "$NGINX_KEY"
    chown root:root "$NGINX_CERT" "$NGINX_KEY"
    systemctl reload nginx || true
fi

# webmin
if [ "$HAS_WEBMIN" -eq 1 ]; then
    mkdir -p "$(dirname "$WEBMIN_CERT")"
    cp -f "$FULLCHAIN" "$WEBMIN_CERT"
    cp -f "$KEY_FILE" "$WEBMIN_KEY"
    chmod 600 "$WEBMIN_CERT" "$WEBMIN_KEY"
    chown root:root "$WEBMIN_CERT" "$WEBMIN_KEY"
    systemctl restart webmin || true
fi

# x-ui / 3x-ui
if [ "$HAS_XUI" -eq 1 ]; then
    UI_CERT_DIR="$ROOT_CERT_BASE/$DOMAIN"
    mkdir -p "$UI_CERT_DIR"
    cp -f "$FULLCHAIN" "$UI_CERT_DIR/fullchain.pem"
    cp -f "$KEY_FILE" "$UI_CERT_DIR/privkey.pem"
    chmod 600 "$UI_CERT_DIR/fullchain.pem" "$UI_CERT_DIR/privkey.pem"
    chown root:root "$UI_CERT_DIR/fullchain.pem" "$UI_CERT_DIR/privkey.pem"
    if svc_exists x-ui || has_cmd x-ui; then
        systemctl restart x-ui || true
    fi
fi

# xray
if [ "$HAS_XRAY" -eq 1 ]; then
    XRAY_CERT_DIR="/etc/xray"
    cp -f "$FULLCHAIN" "$XRAY_CERT_DIR/xray.crt"
    cp -f "$KEY_FILE" "$XRAY_CERT_DIR/xray.key"
    chmod 600 "$XRAY_CERT_DIR/xray.crt" "$XRAY_CERT_DIR/xray.key"
    systemctl restart xray || true
fi

# trojan-go
if [ "$HAS_TROJAN_GO" -eq 1 ]; then
    TROJAN_CERT_DIR="/etc/trojan-go"
    cp -f "$FULLCHAIN" "$TROJAN_CERT_DIR/trojan-go.crt"
    cp -f "$KEY_FILE" "$TROJAN_CERT_DIR/trojan-go.key"
    chmod 600 "$TROJAN_CERT_DIR/trojan-go.crt" "$TROJAN_CERT_DIR/trojan-go.key"
    systemctl restart trojan-go || true
fi

# Part 2/3 ends here (182+ lines)

########################
# permissions & summary
########################
echo
echo "===== Success! ====="
echo "Certificates installed:"
if [ "$HAS_STUNNEL5" -eq 1 ] || [ "$HAS_STUNNEL4" -eq 1 ]; then
    echo "  Stunnel Cert: $STUNNEL_CERT"
    echo "  Stunnel Key : $STUNNEL_KEY"
fi
if [ "$HAS_NGINX" -eq 1 ]; then
    echo "  Nginx Cert  : $NGINX_CERT"
    echo "  Nginx Key   : $NGINX_KEY"
fi
if [ "$HAS_WEBMIN" -eq 1 ]; then
    echo "  Webmin Cert : $WEBMIN_CERT"
    echo "  Webmin Key  : $WEBMIN_KEY"
fi
if [ "$HAS_XUI" -eq 1 ]; then
    echo "  3x-ui/x-ui dir: $UI_CERT_DIR (fullchain.pem / privkey.pem)"
fi
if [ "$HAS_XRAY" -eq 1 ]; then
    echo "  Xray Cert   : $XRAY_CERT_DIR/xray.crt"
    echo "  Xray Key    : $XRAY_CERT_DIR/xray.key"
fi
if [ "$HAS_TROJAN_GO" -eq 1 ]; then
    echo "  Trojan-go Cert: $TROJAN_CERT_DIR/trojan-go.crt"
    echo "  Trojan-go Key : $TROJAN_CERT_DIR/trojan-go.key"
fi
echo "Wildcard domain ready: *.$DOMAIN"
echo "Backup of previous certs in: $BACKUP_DIR"
echo "Log file: $LOG_FILE"
echo "Certificates will auto-renew via acme.sh cron."
echo

########################
# systemd path watcher for auto SSL reload
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

reload_if_active(){ svc="$1"; if systemctl is-active --quiet "$svc"; then systemctl restart "$svc" && echo "[AUTO-SSL] restarted $svc" || echo "[AUTO-SSL] failed to restart $svc"; fi }

# reload services if certs exist
if [[ -f "$STUNNEL_CERT" && -f "$STUNNEL_KEY" ]]; then
    reload_if_active "stunnel5" || reload_if_active "stunnel"
fi
if [[ -f "$NGINX_CERT" && -f "$NGINX_KEY" ]]; then
    reload_if_active "nginx"
fi
if [[ -f "$WEBMIN_CERT" && -f "$WEBMIN_KEY" ]]; then
    reload_if_active "webmin"
fi
if command -v x-ui >/dev/null 2>&1 || systemctl list-units --type=service --all | grep -q "x-ui"; then
    reload_if_active "x-ui"
fi

# Update 3x-ui domain certs
if [ -d "$ROOT_CERT_BASE" ]; then
    for d in "$ROOT_CERT_BASE"/*; do
        if [ -d "$d" ]; then
            if [[ -f "$NGINX_CERT" && -f "$NGINX_KEY" ]]; then
                cp -f "$NGINX_CERT" "$d/fullchain.pem" || true
                cp -f "$NGINX_KEY" "$d/privkey.pem" || true
                chmod 600 "$d/fullchain.pem" "$d/privkey.pem" || true
            fi
        fi
    done
fi
EOF

chmod +x "$AUTO_SSL_SCRIPT"

########################
# systemd path unit
########################
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
# Final cleanup: backup rotation already applied
########################
echo "[INFO] Done."
exit 0
