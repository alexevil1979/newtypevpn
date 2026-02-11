"""
Тесты веб-панели администратора ShadowTunnel.
"""

import os
import sys
import pytest
from unittest.mock import patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from admin.auth import JWTManager, PasswordManager, CSRFProtection


class TestJWTManager:
    """Тесты JWT-аутентификации."""

    def setup_method(self):
        self.jwt = JWTManager("test-secret-key", token_ttl=3600)

    def test_create_and_verify_token(self):
        """Токен создаётся и верифицируется."""
        token = self.jwt.create_token("admin")
        payload = self.jwt.verify_token(token)
        
        assert payload is not None
        assert payload["sub"] == "admin"

    def test_expired_token_rejected(self):
        """Просроченный токен отвергается."""
        jwt = JWTManager("secret", token_ttl=0)  # TTL = 0 секунд
        token = jwt.create_token("admin")
        
        import time
        time.sleep(1)
        
        payload = jwt.verify_token(token)
        assert payload is None

    def test_tampered_token_rejected(self):
        """Изменённый токен отвергается."""
        token = self.jwt.create_token("admin")
        tampered = token[:-5] + "XXXXX"
        
        payload = self.jwt.verify_token(tampered)
        assert payload is None

    def test_invalid_format_rejected(self):
        """Невалидный формат токена отвергается."""
        assert self.jwt.verify_token("not-a-token") is None
        assert self.jwt.verify_token("") is None
        assert self.jwt.verify_token("a.b") is None

    def test_wrong_secret_rejected(self):
        """Токен, подписанный другим секретом, отвергается."""
        jwt1 = JWTManager("secret1")
        jwt2 = JWTManager("secret2")
        
        token = jwt1.create_token("admin")
        
        assert jwt2.verify_token(token) is None

    def test_extra_payload(self):
        """Дополнительные данные сохраняются в токене."""
        token = self.jwt.create_token("admin", extra={"role": "superadmin"})
        payload = self.jwt.verify_token(token)
        
        assert payload["role"] == "superadmin"


class TestPasswordManager:
    """Тесты управления паролями."""

    def test_hash_and_verify(self):
        """Пароль хешируется и верифицируется."""
        password = "strongpassword123"
        hashed = PasswordManager.hash_password(password)
        
        assert hashed != password
        assert PasswordManager.verify_password(password, hashed)

    def test_wrong_password_rejected(self):
        """Неверный пароль не проходит проверку."""
        hashed = PasswordManager.hash_password("correct")
        
        assert not PasswordManager.verify_password("wrong", hashed)

    def test_hash_is_unique(self):
        """Два хеша одного пароля различаются (разные salt)."""
        h1 = PasswordManager.hash_password("same")
        h2 = PasswordManager.hash_password("same")
        
        assert h1 != h2  # Разные salt

    def test_empty_password_handling(self):
        """Пустой пароль обрабатывается корректно."""
        hashed = PasswordManager.hash_password("")
        assert PasswordManager.verify_password("", hashed)
        assert not PasswordManager.verify_password("notempty", hashed)


class TestCSRFProtection:
    """Тесты CSRF-защиты."""

    def setup_method(self):
        self.csrf = CSRFProtection("csrf-secret")

    def test_generate_and_verify(self):
        """CSRF-токен генерируется и верифицируется."""
        token = self.csrf.generate_token("session123")
        assert self.csrf.verify_token(token, "session123")

    def test_wrong_session_rejected(self):
        """CSRF-токен не подходит для другой сессии."""
        token = self.csrf.generate_token("session1")
        assert not self.csrf.verify_token(token, "session2")

    def test_expired_token_rejected(self):
        """Просроченный CSRF-токен отвергается."""
        # Создаём токен с timestamp в прошлом
        import time
        old_time = str(int(time.time()) - 7200)  # 2 часа назад
        import hmac as hmac_module
        import hashlib
        message = f"session1:{old_time}"
        sig = hmac_module.new(
            b"csrf-secret", message.encode(), hashlib.sha256
        ).hexdigest()
        old_token = f"{old_time}:{sig}"
        
        assert not self.csrf.verify_token(old_token, "session1", max_age=3600)

    def test_tampered_token_rejected(self):
        """Изменённый CSRF-токен отвергается."""
        token = self.csrf.generate_token("session1")
        tampered = token[:-5] + "XXXXX"
        assert not self.csrf.verify_token(tampered, "session1")


class TestAdminAPI:
    """Тесты API admin panel (через httpx TestClient)."""

    @pytest.fixture
    def client(self):
        """Создаёт тестовый клиент FastAPI."""
        from httpx import AsyncClient, ASGITransport
        from admin.app import app, load_admin_config
        
        # Инициализируем конфигурацию с дефолтами
        os.environ["SHADOWTUNNEL_CONFIG"] = "nonexistent.yaml"
        load_admin_config("nonexistent.yaml")
        
        transport = ASGITransport(app=app)
        return AsyncClient(transport=transport, base_url="http://test")

    @pytest.mark.asyncio
    async def test_login_page_accessible(self, client):
        """Страница входа доступна."""
        response = await client.get("/login")
        assert response.status_code == 200
        assert "ShadowTunnel" in response.text

    @pytest.mark.asyncio
    async def test_dashboard_requires_auth(self, client):
        """Dashboard требует аутентификации."""
        response = await client.get("/", follow_redirects=False)
        assert response.status_code == 303  # Redirect to login

    @pytest.mark.asyncio
    async def test_api_status_requires_auth(self, client):
        """API статуса требует аутентификации."""
        response = await client.get("/api/status")
        assert response.status_code == 401

    @pytest.mark.asyncio
    async def test_login_with_default_credentials(self, client):
        """Вход с дефолтными учётными данными."""
        response = await client.post(
            "/login",
            data={"username": "admin", "password": "shadowtunnel"},
            follow_redirects=False,
        )
        assert response.status_code == 303
        assert "access_token" in response.cookies

    @pytest.mark.asyncio
    async def test_login_wrong_password(self, client):
        """Неверный пароль отвергается."""
        response = await client.post(
            "/login",
            data={"username": "admin", "password": "wrong"},
        )
        assert response.status_code == 401
