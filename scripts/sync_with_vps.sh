#!/bin/bash
# ═══════════════════════════════════════════════════════════
# ShadowTunnel — VPS Git Synchronization
#
# Синхронизация локального репозитория с VPS bare-репо.
#
# Использование:
#   ./sync_with_vps.sh --setup user@vps:/path/to/repo.git
#   ./sync_with_vps.sh --sync
#   ./sync_with_vps.sh --pull
#   ./sync_with_vps.sh --push
# ═══════════════════════════════════════════════════════════

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info()  { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
cd "$PROJECT_DIR"

VPS_REMOTE_NAME="vps"
CONFIG_FILE="$PROJECT_DIR/.vps_sync_config"

# ── Функции ───────────────────────────────────────────────

setup_vps_remote() {
    local vps_url="$1"
    
    if [ -z "$vps_url" ]; then
        log_error "Укажите адрес VPS bare-репозитория"
        echo "Пример: $0 --setup user@vps:/opt/shadowtunnel.git"
        exit 1
    fi

    # Сохраняем конфигурацию
    echo "$vps_url" > "$CONFIG_FILE"

    # Инициализируем git если нужно
    if [ ! -d ".git" ]; then
        git init
    fi

    # Добавляем remote
    if git remote get-url "$VPS_REMOTE_NAME" &>/dev/null; then
        git remote set-url "$VPS_REMOTE_NAME" "$vps_url"
        log_info "Remote '$VPS_REMOTE_NAME' обновлён: $vps_url"
    else
        git remote add "$VPS_REMOTE_NAME" "$vps_url"
        log_info "Remote '$VPS_REMOTE_NAME' добавлен: $vps_url"
    fi

    # Проверяем SSH-доступ
    local vps_host=$(echo "$vps_url" | cut -d: -f1)
    log_info "Проверка SSH-доступа к $vps_host..."
    if ssh -o ConnectTimeout=5 -o BatchMode=yes "$vps_host" "echo ok" 2>/dev/null; then
        log_info "SSH-доступ подтверждён"
    else
        log_warn "SSH-доступ не удался. Настройте SSH-ключи:"
        log_warn "  ssh-copy-id $vps_host"
    fi

    # Создаём bare-репо на VPS если не существует
    local vps_path=$(echo "$vps_url" | cut -d: -f2)
    ssh "$vps_host" "
        if [ ! -d '$vps_path' ]; then
            git init --bare '$vps_path'
            echo 'Bare repo created: $vps_path'
        else
            echo 'Bare repo already exists'
        fi
    " 2>/dev/null || log_warn "Не удалось создать bare-репо автоматически"

    log_info "Настройка завершена. Используйте: $0 --sync"
}

check_remote() {
    if ! git remote get-url "$VPS_REMOTE_NAME" &>/dev/null; then
        log_error "VPS remote не настроен. Запустите: $0 --setup user@vps:/path/to/repo.git"
        exit 1
    fi
}

push_to_vps() {
    check_remote
    log_info "Push в VPS..."
    
    local branch=$(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo "main")
    
    if git push "$VPS_REMOTE_NAME" "$branch" 2>&1; then
        log_info "Push в VPS успешен"
    else
        log_warn "Push не удался, пробуем force push..."
        git push -f "$VPS_REMOTE_NAME" "$branch"
    fi
}

pull_from_vps() {
    check_remote
    log_info "Pull с VPS..."
    
    local branch=$(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo "main")
    
    if git pull "$VPS_REMOTE_NAME" "$branch" 2>&1; then
        log_info "Pull с VPS успешен"
    else
        log_warn "Pull не удался. Возможен конфликт."
    fi
}

sync_bidirectional() {
    check_remote
    log_info "Двусторонняя синхронизация..."
    
    local branch=$(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo "main")
    
    # Fetch
    git fetch "$VPS_REMOTE_NAME" 2>/dev/null || true
    
    # Check if we need to pull
    local LOCAL=$(git rev-parse "$branch" 2>/dev/null || echo "")
    local REMOTE=$(git rev-parse "$VPS_REMOTE_NAME/$branch" 2>/dev/null || echo "")
    local BASE=$(git merge-base "$branch" "$VPS_REMOTE_NAME/$branch" 2>/dev/null || echo "")
    
    if [ "$LOCAL" = "$REMOTE" ]; then
        log_info "Репозитории синхронизированы"
    elif [ "$LOCAL" = "$BASE" ]; then
        log_info "VPS впереди, выполняю pull..."
        git pull "$VPS_REMOTE_NAME" "$branch"
    elif [ "$REMOTE" = "$BASE" ]; then
        log_info "Локальный впереди, выполняю push..."
        git push "$VPS_REMOTE_NAME" "$branch"
    else
        log_warn "Diverged! Выполняю pull --rebase + push..."
        git pull --rebase "$VPS_REMOTE_NAME" "$branch"
        git push "$VPS_REMOTE_NAME" "$branch"
    fi
    
    log_info "Синхронизация завершена"
}

show_status() {
    check_remote
    local vps_url=$(git remote get-url "$VPS_REMOTE_NAME")
    local branch=$(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo "main")
    
    echo "VPS Remote: $vps_url"
    echo "Branch:     $branch"
    echo ""
    
    git fetch "$VPS_REMOTE_NAME" 2>/dev/null || true
    
    local ahead=$(git rev-list --count "$VPS_REMOTE_NAME/$branch..HEAD" 2>/dev/null || echo "?")
    local behind=$(git rev-list --count "HEAD..$VPS_REMOTE_NAME/$branch" 2>/dev/null || echo "?")
    
    echo "Local ahead:  $ahead commits"
    echo "Local behind: $behind commits"
}

# ── Обработка аргументов ──────────────────────────────────

case "${1:-}" in
    --setup)
        setup_vps_remote "${2:-}"
        ;;
    --sync)
        sync_bidirectional
        ;;
    --push)
        push_to_vps
        ;;
    --pull)
        pull_from_vps
        ;;
    --status)
        show_status
        ;;
    *)
        echo "ShadowTunnel — VPS Git Sync"
        echo ""
        echo "Использование:"
        echo "  $0 --setup user@vps:/path/to/repo.git  — Настроить VPS remote"
        echo "  $0 --sync                               — Двусторонняя синхронизация"
        echo "  $0 --push                               — Push на VPS"
        echo "  $0 --pull                               — Pull с VPS"
        echo "  $0 --status                             — Показать статус"
        ;;
esac
