"""
ShadowTunnel Protocol — криптографические примитивы.

Используемые алгоритмы:
- AES-256-GCM: симметричное шифрование данных
- X25519: обмен ключами Диффи-Хеллмана (ECDH) для forward secrecy
- Ed25519: цифровые подписи для аутентификации
- HMAC-SHA256: контроль целостности пакетов
- HKDF: деривация ключей из общего секрета
"""

import os
import time
import hmac as hmac_module
import hashlib
import struct
from typing import Tuple, Optional

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.hkdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.exceptions import InvalidSignature, InvalidTag

from .constants import (
    AES_KEY_SIZE,
    AES_NONCE_SIZE,
    HMAC_SIZE,
    CHALLENGE_SIZE,
    X25519_KEY_SIZE,
)


class CryptoError(Exception):
    """Базовое исключение для криптографических ошибок."""
    pass


class ShadowCrypto:
    """
    Криптографический движок ShadowTunnel.
    
    Обеспечивает:
    - Генерацию и управление ключами
    - Шифрование/дешифрование AES-256-GCM
    - Подписи Ed25519
    - Обмен ключами X25519 (ECDH)
    - HMAC для целостности пакетов
    - Деривацию ключей через HKDF
    """

    def __init__(self):
        self._identity_key: Optional[Ed25519PrivateKey] = None
        self._ephemeral_key: Optional[X25519PrivateKey] = None
        self._session_key: Optional[bytes] = None
        self._aesgcm: Optional[AESGCM] = None
        self._hmac_key: Optional[bytes] = None

    # ── Генерация ключей ──────────────────────────────────────────

    @staticmethod
    def generate_identity_keypair() -> Tuple[Ed25519PrivateKey, Ed25519PublicKey]:
        """Генерирует пару ключей Ed25519 для долгосрочной аутентификации."""
        private_key = Ed25519PrivateKey.generate()
        public_key = private_key.public_key()
        return private_key, public_key

    @staticmethod
    def generate_ephemeral_keypair() -> Tuple[X25519PrivateKey, X25519PublicKey]:
        """Генерирует эфемерную пару X25519 для обмена ключами (forward secrecy)."""
        private_key = X25519PrivateKey.generate()
        public_key = private_key.public_key()
        return private_key, public_key

    @staticmethod
    def generate_challenge() -> bytes:
        """Генерирует случайный challenge для аутентификации."""
        return os.urandom(CHALLENGE_SIZE)

    # ── Сериализация ключей ───────────────────────────────────────

    @staticmethod
    def serialize_private_key(key: Ed25519PrivateKey) -> bytes:
        """Сериализует приватный ключ Ed25519 в формат PEM."""
        return key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )

    @staticmethod
    def serialize_public_key(key: Ed25519PublicKey) -> bytes:
        """Сериализует публичный ключ Ed25519 в формат PEM."""
        return key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

    @staticmethod
    def deserialize_private_key(data: bytes) -> Ed25519PrivateKey:
        """Десериализует приватный ключ Ed25519 из PEM."""
        key = serialization.load_pem_private_key(data, password=None)
        if not isinstance(key, Ed25519PrivateKey):
            raise CryptoError("Expected Ed25519 private key")
        return key

    @staticmethod
    def deserialize_public_key(data: bytes) -> Ed25519PublicKey:
        """Десериализует публичный ключ Ed25519 из PEM."""
        key = serialization.load_pem_public_key(data)
        if not isinstance(key, Ed25519PublicKey):
            raise CryptoError("Expected Ed25519 public key")
        return key

    @staticmethod
    def export_x25519_public(key: X25519PublicKey) -> bytes:
        """Экспортирует публичный ключ X25519 в raw-формат (32 байта)."""
        return key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )

    @staticmethod
    def import_x25519_public(data: bytes) -> X25519PublicKey:
        """Импортирует публичный ключ X25519 из raw-формата."""
        if len(data) != X25519_KEY_SIZE:
            raise CryptoError(f"Invalid X25519 public key size: {len(data)}")
        return X25519PublicKey.from_public_bytes(data)

    # ── Обмен ключами (ECDH) ─────────────────────────────────────

    def perform_ecdh(
        self,
        our_private: X25519PrivateKey,
        their_public: X25519PublicKey,
    ) -> bytes:
        """
        Выполняет X25519 ECDH и деривирует сессионные ключи через HKDF.
        
        Returns:
            64 байта: первые 32 — AES ключ, последние 32 — HMAC ключ
        """
        shared_secret = our_private.exchange(their_public)

        derived = HKDF(
            algorithm=hashes.SHA256(),
            length=AES_KEY_SIZE + HMAC_SIZE,
            salt=None,
            info=b"ShadowTunnel-v1-session-keys",
        ).derive(shared_secret)

        self._session_key = derived[:AES_KEY_SIZE]
        self._hmac_key = derived[AES_KEY_SIZE:]
        self._aesgcm = AESGCM(self._session_key)

        return derived

    def set_session_keys(self, aes_key: bytes, hmac_key: bytes):
        """Устанавливает сессионные ключи напрямую (например, после ротации)."""
        if len(aes_key) != AES_KEY_SIZE:
            raise CryptoError(f"Invalid AES key size: {len(aes_key)}")
        if len(hmac_key) != HMAC_SIZE:
            raise CryptoError(f"Invalid HMAC key size: {len(hmac_key)}")
        self._session_key = aes_key
        self._hmac_key = hmac_key
        self._aesgcm = AESGCM(self._session_key)

    # ── Шифрование/Дешифрование AES-256-GCM ──────────────────────

    def encrypt(self, plaintext: bytes, associated_data: bytes = b"") -> Tuple[bytes, bytes]:
        """
        Шифрует данные AES-256-GCM.
        
        Args:
            plaintext: открытый текст
            associated_data: дополнительные аутентифицированные данные (AAD)
            
        Returns:
            (nonce, ciphertext) — nonce 12 байт, ciphertext включает GCM-тег
        """
        if self._aesgcm is None:
            raise CryptoError("Session keys not established")

        nonce = os.urandom(AES_NONCE_SIZE)
        ciphertext = self._aesgcm.encrypt(nonce, plaintext, associated_data)
        return nonce, ciphertext

    def decrypt(
        self,
        nonce: bytes,
        ciphertext: bytes,
        associated_data: bytes = b"",
    ) -> bytes:
        """
        Дешифрует данные AES-256-GCM.
        
        Raises:
            CryptoError: при ошибке дешифрования (повреждённые данные, неверный ключ)
        """
        if self._aesgcm is None:
            raise CryptoError("Session keys not established")

        try:
            return self._aesgcm.decrypt(nonce, ciphertext, associated_data)
        except InvalidTag:
            raise CryptoError("Decryption failed: invalid tag (tampered data?)")

    # ── Подписи Ed25519 ───────────────────────────────────────────

    @staticmethod
    def sign(private_key: Ed25519PrivateKey, data: bytes) -> bytes:
        """Подписывает данные ключом Ed25519."""
        return private_key.sign(data)

    @staticmethod
    def verify_signature(
        public_key: Ed25519PublicKey,
        signature: bytes,
        data: bytes,
    ) -> bool:
        """Проверяет подпись Ed25519. Возвращает True если валидна."""
        try:
            public_key.verify(signature, data)
            return True
        except InvalidSignature:
            return False

    # ── HMAC ──────────────────────────────────────────────────────

    def compute_hmac(self, data: bytes) -> bytes:
        """Вычисляет HMAC-SHA256 для данных."""
        if self._hmac_key is None:
            raise CryptoError("HMAC key not established")
        return hmac_module.new(self._hmac_key, data, hashlib.sha256).digest()

    def verify_hmac(self, data: bytes, expected_hmac: bytes) -> bool:
        """Проверяет HMAC-SHA256. Использует constant-time сравнение."""
        if self._hmac_key is None:
            raise CryptoError("HMAC key not established")
        computed = hmac_module.new(self._hmac_key, data, hashlib.sha256).digest()
        return hmac_module.compare_digest(computed, expected_hmac)

    # ── Деривация ключей для ротации ──────────────────────────────

    def derive_rotation_keys(self, current_key: bytes, rotation_counter: int) -> bytes:
        """
        Деривирует новые сессионные ключи при ротации.
        Использует HKDF с текущим ключом и счётчиком ротации.
        """
        info = b"ShadowTunnel-v1-key-rotation-" + struct.pack("!I", rotation_counter)
        derived = HKDF(
            algorithm=hashes.SHA256(),
            length=AES_KEY_SIZE + HMAC_SIZE,
            salt=current_key,
            info=info,
        ).derive(os.urandom(32))

        self._session_key = derived[:AES_KEY_SIZE]
        self._hmac_key = derived[AES_KEY_SIZE:]
        self._aesgcm = AESGCM(self._session_key)
        return derived

    # ── Утилиты ───────────────────────────────────────────────────

    @property
    def has_session_keys(self) -> bool:
        """Проверяет, установлены ли сессионные ключи."""
        return self._session_key is not None and self._hmac_key is not None

    @property
    def session_key(self) -> Optional[bytes]:
        return self._session_key

    @property
    def hmac_key(self) -> Optional[bytes]:
        return self._hmac_key

    def clear_keys(self):
        """Безопасно очищает все ключи из памяти."""
        self._session_key = None
        self._hmac_key = None
        self._aesgcm = None
        self._ephemeral_key = None
