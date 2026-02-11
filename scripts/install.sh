#!/bin/bash
# ═══════════════════════════════════════════════════════════
# ShadowTunnel Server — Installation Script
# Для Ubuntu 22.04+
# Запуск: sudo ./scripts/install.sh
# ═══════════════════════════════════════════════════════════

set -euo pipefail

# Цвета
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

INSTALL_DIR="/opt/shadowtunnel"
CONFIG_DIR="/etc/shadowtunnel"
LOG_DIR="/var/log/shadowtunnel"
SERVICE_USER="root"

log_info()  { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }
log_step()  { echo -e "${BLUE}[STEP]${NC} $1"; }

# ── Проверки ──────────────────────────────────────────────

if [ "$(id -u)" -ne 0 ]; then
    log_error "Запустите скрипт с правами root: sudo $0"
    exit 1
fi

if ! grep -q "Ubuntu" /etc/os-release 2>/dev/null; then
    log_warn "Скрипт оптимизирован для Ubuntu, но может работать на других дистрибутивах"
fi

echo ""
echo "════════════════════════════════════════════════════"
echo "   ShadowTunnel Server — Установка v1.0.0"
echo "════════════════════════════════════════════════════"
echo ""

# ── Шаг 1: Установка зависимостей ────────────────────────

log_step "1/8: Установка системных зависимостей..."
apt-get update -qq
apt-get install -y -qq \
    python3 python3-pip python3-venv \
    git curl wget \
    iptables \
    openssl \
    ufw \
    > /dev/null 2>&1
log_info "Зависимости установлены"

# ── Шаг 2: Создание директорий ───────────────────────────

log_step "2/8: Создание директорий..."
mkdir -p "$INSTALL_DIR"
mkdir -p "$CONFIG_DIR"
mkdir -p "$LOG_DIR"
chmod 700 "$CONFIG_DIR"
chmod 755 "$LOG_DIR"
log_info "Директории созданы"

# ── Шаг 3: Копирование файлов ────────────────────────────

log_step "3/8: Копирование файлов проекта..."
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

# Копируем весь проект
cp -r "$PROJECT_DIR/server" "$INSTALL_DIR/"
cp -r "$PROJECT_DIR/shared" "$INSTALL_DIR/"
cp -r "$PROJECT_DIR/admin" "$INSTALL_DIR/"

# Копируем конфигурацию
if [ ! -f "$CONFIG_DIR/config.yaml" ]; then
    cp "$PROJECT_DIR/server/config.yaml" "$CONFIG_DIR/config.yaml"
    log_info "Конфигурация скопирована в $CONFIG_DIR/config.yaml"
else
    log_warn "Конфигурация уже существует, пропускаю"
fi
log_info "Файлы скопированы"

# ── Шаг 4: Python virtual environment ────────────────────

log_step "4/8: Настройка Python окружения..."
python3 -m venv "$INSTALL_DIR/venv"
source "$INSTALL_DIR/venv/bin/activate"
pip install --upgrade pip -q
pip install -r "$PROJECT_DIR/server/requirements.txt" -q
pip install -r "$PROJECT_DIR/admin/requirements.txt" -q
deactivate
log_info "Python окружение настроено"

# ── Шаг 5: Генерация ключей ──────────────────────────────

log_step "5/8: Генерация криптографических ключей..."

# Серверные ключи Ed25519
if [ ! -f "$CONFIG_DIR/server.key" ]; then
    "$INSTALL_DIR/venv/bin/python3" "$PROJECT_DIR/scripts/generate_keys.py" \
        --output-dir "$CONFIG_DIR" \
        --type server
    chmod 600 "$CONFIG_DIR/server.key"
    log_info "Серверные ключи сгенерированы"
else
    log_warn "Серверные ключи уже существуют"
fi

# SSL-сертификат для admin panel
if [ ! -f "$CONFIG_DIR/admin.crt" ]; then
    openssl req -x509 -newkey rsa:2048 -nodes \
        -keyout "$CONFIG_DIR/admin.key" \
        -out "$CONFIG_DIR/admin.crt" \
        -days 3650 \
        -subj "/CN=ShadowTunnel Admin" \
        2>/dev/null
    chmod 600 "$CONFIG_DIR/admin.key"
    log_info "SSL-сертификат для admin panel сгенерирован"
fi

# JWT secret
JWT_SECRET=$(openssl rand -hex 32)
sed -i "s/jwt_secret: \"\"/jwt_secret: \"$JWT_SECRET\"/" "$CONFIG_DIR/config.yaml" 2>/dev/null || true

# Default admin password hash
ADMIN_HASH=$("$INSTALL_DIR/venv/bin/python3" -c "
import bcrypt
h = bcrypt.hashpw(b'shadowtunnel', bcrypt.gensalt(12))
print(h.decode())
")
sed -i "s|password_hash: \"\"|password_hash: \"$ADMIN_HASH\"|" "$CONFIG_DIR/config.yaml" 2>/dev/null || true

log_info "Ключи и сертификаты настроены"

# ── Шаг 6: Настройка firewall ────────────────────────────

log_step "6/8: Настройка firewall (ufw)..."
ufw allow 51820/udp comment "ShadowTunnel VPN" > /dev/null 2>&1 || true
ufw allow 22/tcp comment "SSH" > /dev/null 2>&1 || true

# Включаем IP forwarding
if ! grep -q "net.ipv4.ip_forward=1" /etc/sysctl.conf; then
    echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
fi
sysctl -w net.ipv4.ip_forward=1 > /dev/null 2>&1

log_info "Firewall настроен"

# ── Шаг 7: Установка systemd-сервиса ─────────────────────

log_step "7/8: Установка systemd-сервиса..."
cp "$PROJECT_DIR/server/shadowtunnel.service" /etc/systemd/system/shadowtunnel.service
systemctl daemon-reload
systemctl enable shadowtunnel
log_info "Сервис установлен и включён"

# ── Шаг 8: SSH ключи для VPS sync ────────────────────────

log_step "8/8: Проверка SSH-ключей..."
if [ ! -f "$HOME/.ssh/id_ed25519" ]; then
    ssh-keygen -t ed25519 -f "$HOME/.ssh/id_ed25519" -N "" -q
    log_info "SSH-ключ сгенерирован: $HOME/.ssh/id_ed25519.pub"
else
    log_warn "SSH-ключ уже существует"
fi

# ── Готово ────────────────────────────────────────────────

echo ""
echo "════════════════════════════════════════════════════"
echo -e "   ${GREEN}Установка завершена!${NC}"
echo "════════════════════════════════════════════════════"
echo ""
echo "  Следующие шаги:"
echo ""
echo "  1. Отредактируйте конфигурацию:"
echo "     nano $CONFIG_DIR/config.yaml"
echo ""
echo "  2. Запустите сервер:"
echo "     systemctl start shadowtunnel"
echo ""
echo "  3. Проверьте статус:"
echo "     systemctl status shadowtunnel"
echo ""
echo "  4. Admin panel (дефолт: admin/shadowtunnel):"
echo "     https://localhost:8443"
echo ""
echo "  5. Логи:"
echo "     journalctl -u shadowtunnel -f"
echo ""
echo "  Публичный ключ сервера:"
if [ -f "$CONFIG_DIR/server.pub" ]; then
    cat "$CONFIG_DIR/server.pub"
fi
echo ""
