"""
ShadowTunnel Admin — JWT-аутентификация.

Обеспечивает:
- Хеширование паролей (bcrypt)
- Выпуск и проверку JWT-токенов
- Middleware для защиты маршрутов
"""

import os
import time
import hashlib
import hmac
import json
import base64
import secrets
from typing import Optional
from functools import wraps

import bcrypt


class AuthError(Exception):
    """Ошибка аутентификации."""
    pass


class JWTManager:
    """
    Простая JWT-реализация без внешних зависимостей.
    Использует HMAC-SHA256 для подписи.
    """

    def __init__(self, secret: str, token_ttl: int = 3600):
        """
        Args:
            secret: секретный ключ для подписи
            token_ttl: время жизни токена в секундах (по умолчанию 1 час)
        """
        if not secret:
            secret = secrets.token_hex(32)
        self._secret = secret.encode("utf-8")
        self._ttl = token_ttl

    def create_token(self, username: str, extra: dict = None) -> str:
        """Создаёт JWT-токен."""
        header = {"alg": "HS256", "typ": "JWT"}
        payload = {
            "sub": username,
            "iat": int(time.time()),
            "exp": int(time.time()) + self._ttl,
        }
        if extra:
            payload.update(extra)

        header_b64 = self._b64encode(json.dumps(header))
        payload_b64 = self._b64encode(json.dumps(payload))

        message = f"{header_b64}.{payload_b64}"
        signature = hmac.new(
            self._secret, message.encode("utf-8"), hashlib.sha256
        ).digest()
        sig_b64 = self._b64encode_bytes(signature)

        return f"{header_b64}.{payload_b64}.{sig_b64}"

    def verify_token(self, token: str) -> Optional[dict]:
        """
        Проверяет JWT-токен.
        
        Returns:
            Payload словарь или None если токен невалиден
        """
        try:
            parts = token.split(".")
            if len(parts) != 3:
                return None

            header_b64, payload_b64, sig_b64 = parts

            # Проверяем подпись
            message = f"{header_b64}.{payload_b64}"
            expected_sig = hmac.new(
                self._secret, message.encode("utf-8"), hashlib.sha256
            ).digest()
            actual_sig = self._b64decode_bytes(sig_b64)

            if not hmac.compare_digest(expected_sig, actual_sig):
                return None

            # Декодируем payload
            payload = json.loads(self._b64decode(payload_b64))

            # Проверяем срок действия
            if payload.get("exp", 0) < time.time():
                return None

            return payload

        except Exception:
            return None

    @staticmethod
    def _b64encode(data: str) -> str:
        return base64.urlsafe_b64encode(data.encode("utf-8")).rstrip(b"=").decode("utf-8")

    @staticmethod
    def _b64encode_bytes(data: bytes) -> str:
        return base64.urlsafe_b64encode(data).rstrip(b"=").decode("utf-8")

    @staticmethod
    def _b64decode(data: str) -> str:
        padding = 4 - len(data) % 4
        data += "=" * padding
        return base64.urlsafe_b64decode(data).decode("utf-8")

    @staticmethod
    def _b64decode_bytes(data: str) -> bytes:
        padding = 4 - len(data) % 4
        data += "=" * padding
        return base64.urlsafe_b64decode(data)


class PasswordManager:
    """Управление паролями с bcrypt."""

    @staticmethod
    def hash_password(password: str) -> str:
        """Хеширует пароль с bcrypt."""
        salt = bcrypt.gensalt(rounds=12)
        hashed = bcrypt.hashpw(password.encode("utf-8"), salt)
        return hashed.decode("utf-8")

    @staticmethod
    def verify_password(password: str, hashed: str) -> bool:
        """Проверяет пароль против хеша."""
        try:
            return bcrypt.checkpw(
                password.encode("utf-8"),
                hashed.encode("utf-8"),
            )
        except Exception:
            return False


# CSRF-защита
class CSRFProtection:
    """Генерация и проверка CSRF-токенов."""

    def __init__(self, secret: str):
        self._secret = secret.encode("utf-8")

    def generate_token(self, session_id: str) -> str:
        """Генерирует CSRF-токен привязанный к сессии."""
        timestamp = str(int(time.time()))
        message = f"{session_id}:{timestamp}"
        sig = hmac.new(self._secret, message.encode("utf-8"), hashlib.sha256).hexdigest()
        return f"{timestamp}:{sig}"

    def verify_token(self, token: str, session_id: str, max_age: int = 3600) -> bool:
        """Проверяет CSRF-токен."""
        try:
            parts = token.split(":")
            if len(parts) != 2:
                return False
            timestamp, sig = parts

            # Проверяем возраст
            if int(time.time()) - int(timestamp) > max_age:
                return False

            # Проверяем подпись
            message = f"{session_id}:{timestamp}"
            expected = hmac.new(
                self._secret, message.encode("utf-8"), hashlib.sha256
            ).hexdigest()
            return hmac.compare_digest(expected, sig)
        except Exception:
            return False
