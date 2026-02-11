#!/usr/bin/env python3
"""
ShadowTunnel Admin — веб-панель администратора.

FastAPI-приложение с:
- JWT-аутентификацией
- Управлением клиентами и ключами
- Мониторингом сессий
- Управлением сервисом
- Защитой от CSRF/XSS
"""

import os
import sys
import time
import pathlib
import logging
import secrets
import subprocess
from typing import Optional
from datetime import datetime

import yaml
from fastapi import FastAPI, Request, Response, Depends, HTTPException, Form, Cookie
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import uvicorn

PROJECT_ROOT = str(pathlib.Path(__file__).resolve().parents[1])
sys.path.insert(0, PROJECT_ROOT)

from admin.auth import JWTManager, PasswordManager, CSRFProtection

logger = logging.getLogger("shadowtunnel.admin")

# ── Инициализация приложения ──────────────────────────────────────

app = FastAPI(
    title="ShadowTunnel Admin",
    description="Панель администрирования ShadowTunnel VPN",
    version="1.0.0",
    docs_url=None,  # Скрываем Swagger в production
    redoc_url=None,
)

# Static files и Templates
BASE_DIR = pathlib.Path(__file__).resolve().parent
app.mount("/static", StaticFiles(directory=str(BASE_DIR / "static")), name="static")
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))

# ── Конфигурация ──────────────────────────────────────────────────

CONFIG = {}
JWT_MANAGER: Optional[JWTManager] = None
CSRF: Optional[CSRFProtection] = None
ADMIN_USERNAME = "admin"
ADMIN_PASSWORD_HASH = ""

# In-memory storage для сессий и логов
CONNECTED_CLIENTS = []
TRAFFIC_LOGS = []
MAX_LOG_ENTRIES = 1000


def load_admin_config(config_path: str = "server/config.yaml"):
    """Загружает конфигурацию для admin panel."""
    global CONFIG, JWT_MANAGER, CSRF, ADMIN_USERNAME, ADMIN_PASSWORD_HASH

    try:
        with open(config_path, "r", encoding="utf-8") as f:
            CONFIG = yaml.safe_load(f)
    except FileNotFoundError:
        CONFIG = {}
        logger.warning(f"Config not found at {config_path}, using defaults")

    admin_cfg = CONFIG.get("admin", {})
    jwt_secret = admin_cfg.get("jwt_secret", "") or secrets.token_hex(32)
    JWT_MANAGER = JWTManager(jwt_secret, token_ttl=3600)
    CSRF = CSRFProtection(jwt_secret)

    ADMIN_USERNAME = admin_cfg.get("username", "admin")
    ADMIN_PASSWORD_HASH = admin_cfg.get("password_hash", "")

    # Если хеш пуст — создаём дефолтный пароль
    if not ADMIN_PASSWORD_HASH:
        default_pass = "shadowtunnel"
        ADMIN_PASSWORD_HASH = PasswordManager.hash_password(default_pass)
        logger.warning(
            f"No admin password configured! Default: {ADMIN_USERNAME}/{default_pass}"
        )


# ── Middleware ────────────────────────────────────────────────────

@app.middleware("http")
async def security_headers(request: Request, call_next):
    """Добавляет заголовки безопасности."""
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "font-src 'self' https://fonts.gstatic.com; "
        "script-src 'self' 'unsafe-inline';"
    )
    return response


# ── Зависимости ──────────────────────────────────────────────────

async def get_current_user(request: Request) -> Optional[str]:
    """Извлекает текущего пользователя из JWT cookie."""
    token = request.cookies.get("access_token")
    if not token:
        return None
    if JWT_MANAGER is None:
        return None
    payload = JWT_MANAGER.verify_token(token)
    if payload:
        return payload.get("sub")
    return None


async def require_auth(request: Request) -> str:
    """Требует аутентификацию. Redirect на login если нет."""
    user = await get_current_user(request)
    if not user:
        raise HTTPException(status_code=303, headers={"Location": "/login"})
    return user


# ── Маршруты: Аутентификация ─────────────────────────────────────

@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    """Страница входа."""
    user = await get_current_user(request)
    if user:
        return RedirectResponse(url="/", status_code=303)
    return templates.TemplateResponse("login.html", {
        "request": request,
        "error": None,
    })


@app.post("/login")
async def login(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
):
    """Обработка входа."""
    if username != ADMIN_USERNAME:
        return templates.TemplateResponse("login.html", {
            "request": request,
            "error": "Неверное имя пользователя или пароль",
        }, status_code=401)

    if not PasswordManager.verify_password(password, ADMIN_PASSWORD_HASH):
        logger.warning(f"Failed login attempt for {username} from {request.client.host}")
        return templates.TemplateResponse("login.html", {
            "request": request,
            "error": "Неверное имя пользователя или пароль",
        }, status_code=401)

    # Создаём JWT
    token = JWT_MANAGER.create_token(username)

    response = RedirectResponse(url="/", status_code=303)
    response.set_cookie(
        key="access_token",
        value=token,
        httponly=True,
        secure=True,
        samesite="strict",
        max_age=3600,
    )

    logger.info(f"Admin login: {username} from {request.client.host}")
    return response


@app.get("/logout")
async def logout():
    """Выход."""
    response = RedirectResponse(url="/login", status_code=303)
    response.delete_cookie("access_token")
    return response


# ── Маршруты: Dashboard ──────────────────────────────────────────

@app.get("/", response_class=HTMLResponse)
async def dashboard(request: Request):
    """Главная страница — dashboard."""
    user = await get_current_user(request)
    if not user:
        return RedirectResponse(url="/login", status_code=303)

    return templates.TemplateResponse("dashboard.html", {
        "request": request,
        "user": user,
        "clients": CONNECTED_CLIENTS,
        "client_count": len(CONNECTED_CLIENTS),
        "server_uptime": _get_uptime(),
        "total_traffic": _get_total_traffic(),
    })


@app.get("/clients", response_class=HTMLResponse)
async def clients_page(request: Request):
    """Страница управления клиентами."""
    user = await get_current_user(request)
    if not user:
        return RedirectResponse(url="/login", status_code=303)

    return templates.TemplateResponse("clients.html", {
        "request": request,
        "user": user,
        "clients": CONNECTED_CLIENTS,
    })


# ── API маршруты ─────────────────────────────────────────────────

@app.get("/api/status")
async def api_status(request: Request):
    """API: Статус сервера."""
    user = await get_current_user(request)
    if not user:
        raise HTTPException(status_code=401, detail="Unauthorized")

    return {
        "status": "running",
        "uptime": _get_uptime(),
        "clients_connected": len(CONNECTED_CLIENTS),
        "total_traffic": _get_total_traffic(),
        "timestamp": time.time(),
    }


@app.get("/api/clients")
async def api_clients(request: Request):
    """API: Список подключённых клиентов."""
    user = await get_current_user(request)
    if not user:
        raise HTTPException(status_code=401, detail="Unauthorized")

    return {"clients": CONNECTED_CLIENTS}


@app.get("/api/logs")
async def api_logs(request: Request, limit: int = 50):
    """API: Последние записи лога."""
    user = await get_current_user(request)
    if not user:
        raise HTTPException(status_code=401, detail="Unauthorized")

    return {"logs": TRAFFIC_LOGS[-limit:]}


class ClientKeyRequest(BaseModel):
    name: str
    public_key: str


@app.post("/api/clients/add")
async def api_add_client(request: Request, body: ClientKeyRequest):
    """API: Добавить авторизованный ключ клиента."""
    user = await get_current_user(request)
    if not user:
        raise HTTPException(status_code=401, detail="Unauthorized")

    # Добавляем в конфигурацию
    if "auth" not in CONFIG:
        CONFIG["auth"] = {"clients": []}
    CONFIG["auth"]["clients"].append({
        "name": body.name,
        "public_key": body.public_key,
    })

    return {"status": "ok", "message": f"Client '{body.name}' added"}


@app.post("/api/service/restart")
async def api_restart_service(request: Request):
    """API: Перезапуск сервиса."""
    user = await get_current_user(request)
    if not user:
        raise HTTPException(status_code=401, detail="Unauthorized")

    try:
        subprocess.run(
            ["systemctl", "restart", "shadowtunnel"],
            check=True,
            timeout=10,
        )
        return {"status": "ok", "message": "Service restarted"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


class ConfigUpdate(BaseModel):
    config_yaml: str


@app.post("/api/config/update")
async def api_update_config(request: Request, body: ConfigUpdate):
    """API: Обновить конфигурацию."""
    user = await get_current_user(request)
    if not user:
        raise HTTPException(status_code=401, detail="Unauthorized")

    try:
        # Валидируем YAML
        new_config = yaml.safe_load(body.config_yaml)
        if not isinstance(new_config, dict):
            raise ValueError("Invalid YAML structure")

        config_path = os.environ.get(
            "SHADOWTUNNEL_CONFIG", "server/config.yaml"
        )
        with open(config_path, "w", encoding="utf-8") as f:
            yaml.dump(new_config, f, default_flow_style=False)

        return {"status": "ok", "message": "Configuration updated"}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


# ── Вспомогательные функции ──────────────────────────────────────

_start_time = time.time()


def _get_uptime() -> str:
    """Возвращает uptime в читаемом формате."""
    seconds = int(time.time() - _start_time)
    days, remainder = divmod(seconds, 86400)
    hours, remainder = divmod(remainder, 3600)
    minutes, secs = divmod(remainder, 60)
    parts = []
    if days:
        parts.append(f"{days}д")
    if hours:
        parts.append(f"{hours}ч")
    parts.append(f"{minutes}м {secs}с")
    return " ".join(parts)


def _get_total_traffic() -> dict:
    """Суммарный трафик."""
    total_sent = sum(c.get("bytes_sent", 0) for c in CONNECTED_CLIENTS)
    total_recv = sum(c.get("bytes_received", 0) for c in CONNECTED_CLIENTS)
    return {
        "sent": _format_bytes(total_sent),
        "received": _format_bytes(total_recv),
        "sent_raw": total_sent,
        "received_raw": total_recv,
    }


def _format_bytes(b: int) -> str:
    """Форматирует байты в человекочитаемый формат."""
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if b < 1024:
            return f"{b:.1f} {unit}"
        b /= 1024
    return f"{b:.1f} PB"


# ── Startup/Shutdown ─────────────────────────────────────────────

@app.on_event("startup")
async def startup():
    config_path = os.environ.get("SHADOWTUNNEL_CONFIG", "server/config.yaml")
    load_admin_config(config_path)
    logger.info("Admin panel started")


# ── Запуск ────────────────────────────────────────────────────────

def run_admin(
    host: str = "127.0.0.1",
    port: int = 8443,
    ssl_cert: str = None,
    ssl_key: str = None,
):
    """Запускает admin panel."""
    kwargs = {
        "host": host,
        "port": port,
        "log_level": "info",
    }
    if ssl_cert and ssl_key:
        kwargs["ssl_certfile"] = ssl_cert
        kwargs["ssl_keyfile"] = ssl_key

    uvicorn.run(app, **kwargs)


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="ShadowTunnel Admin Panel")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8443)
    parser.add_argument("--ssl-cert", default=None)
    parser.add_argument("--ssl-key", default=None)
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO)
    run_admin(args.host, args.port, args.ssl_cert, args.ssl_key)
