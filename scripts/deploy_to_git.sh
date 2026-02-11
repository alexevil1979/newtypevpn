#!/bin/bash
# ═══════════════════════════════════════════════════════════
# ShadowTunnel — Deploy to GitHub
# Коммитит и пушит изменения в GitHub репозиторий
# ═══════════════════════════════════════════════════════════

set -euo pipefail

REPO_URL="https://github.com/alexevil1979/newtypevpn.git"
BRANCH="${1:-main}"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info()  { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

# Определяем директорию проекта
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
cd "$PROJECT_DIR"

# Проверяем, что git настроен
if ! command -v git &> /dev/null; then
    log_error "Git не установлен"
    exit 1
fi

# Инициализируем репозиторий если нужно
if [ ! -d ".git" ]; then
    log_info "Инициализация Git-репозитория..."
    git init
    git remote add origin "$REPO_URL" 2>/dev/null || true
fi

# Проверяем remote
CURRENT_REMOTE=$(git remote get-url origin 2>/dev/null || echo "")
if [ "$CURRENT_REMOTE" != "$REPO_URL" ]; then
    log_warn "Remote 'origin' не совпадает, обновляю..."
    git remote set-url origin "$REPO_URL" 2>/dev/null || git remote add origin "$REPO_URL"
fi

# Проверяем наличие изменений
if git diff --quiet && git diff --cached --quiet && [ -z "$(git ls-files --others --exclude-standard)" ]; then
    log_info "Нет изменений для коммита"
    exit 0
fi

# Добавляем все файлы
log_info "Добавление файлов..."
git add -A

# Исключаем секреты
git reset HEAD -- "*.key" "*.pem" "server/config.local.yaml" 2>/dev/null || true

# Формируем сообщение коммита
TIMESTAMP=$(date "+%Y-%m-%d %H:%M:%S")
COMMIT_MSG="deploy: update ShadowTunnel — $TIMESTAMP"

# Проверяем если есть что коммитить после reset
if git diff --cached --quiet; then
    log_info "Нет изменений после исключения секретов"
    exit 0
fi

log_info "Создание коммита..."
git commit -m "$COMMIT_MSG"

# Push
log_info "Push в $REPO_URL ($BRANCH)..."
if git push -u origin "$BRANCH" 2>&1; then
    log_info "Успешно запушено в GitHub!"
else
    log_warn "Push не удался. Проверьте аутентификацию."
    log_warn "Для HTTPS: git config credential.helper store"
    log_warn "Для SSH:   git remote set-url origin git@github.com:alexevil1979/newtypevpn.git"
    exit 1
fi

echo ""
log_info "Деплой завершён: $REPO_URL"
