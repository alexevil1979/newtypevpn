"""
ShadowTunnel Protocol — константы и конфигурация протокола.
"""

import os
import struct

# ── Версия протокола ──────────────────────────────────────────────
PROTOCOL_VERSION = 1

# ── Сетевые параметры ─────────────────────────────────────────────
DEFAULT_SERVER_PORT = 51820
DEFAULT_ADMIN_PORT = 8443
MAX_PACKET_SIZE = 1500          # MTU-safe
MIN_PACKET_SIZE = 64            # Минимальный размер (с padding)
MAX_PAYLOAD_SIZE = 1400         # Максимальный размер полезной нагрузки

# ── Криптографические параметры ───────────────────────────────────
AES_KEY_SIZE = 32               # 256 бит
AES_NONCE_SIZE = 12             # 96 бит для GCM
HMAC_SIZE = 32                  # SHA-256
ED25519_SIG_SIZE = 64
X25519_KEY_SIZE = 32
SESSION_ID_SIZE = 16            # 128 бит
CHALLENGE_SIZE = 32             # 256 бит
MAGIC_SIZE = 4                  # Магические байты (рандомизируются)

# ── Временные параметры ───────────────────────────────────────────
KEY_ROTATION_INTERVAL = 1800    # 30 минут в секундах
REPLAY_WINDOW_SIZE = 1024       # Размер окна anti-replay
TIMESTAMP_TOLERANCE = 30        # Допустимое отклонение времени (сек)
HANDSHAKE_TIMEOUT = 10          # Таймаут рукопожатия (сек)
KEEPALIVE_INTERVAL = 25         # Интервал keepalive (сек)
SESSION_TIMEOUT = 300           # Таймаут неактивной сессии (сек)
RECONNECT_DELAY_BASE = 1       # Базовая задержка переподключения
RECONNECT_DELAY_MAX = 60       # Максимальная задержка

# ── Типы пакетов ──────────────────────────────────────────────────
class PacketType:
    """Типы пакетов протокола ShadowTunnel."""
    INIT_HELLO = 0x01           # Клиент -> Сервер: инициация
    INIT_CHALLENGE = 0x02       # Сервер -> Клиент: вызов (challenge)
    INIT_RESPONSE = 0x03        # Клиент -> Сервер: ответ на вызов
    INIT_CONFIRM = 0x04         # Сервер -> Клиент: подтверждение сессии
    DATA = 0x10                 # Зашифрованные данные
    KEEPALIVE = 0x20            # Keepalive
    KEY_ROTATE = 0x30           # Запрос ротации ключей
    KEY_ROTATE_ACK = 0x31       # Подтверждение ротации
    DISCONNECT = 0xFF           # Разрыв соединения


# ── Формат заголовка пакета ───────────────────────────────────────
# Все значения в network byte order (big-endian)
#
# Offset  Size  Field
# 0       4     magic (рандомизируется per-session)
# 4       1     packet_type
# 5       16    session_id
# 21      8     timestamp (uint64, unix epoch ms)
# 29      4     sequence_number (uint32)
# 33      12    nonce (для AES-GCM)
# 45      2     payload_length (uint16)
# 47      ...   encrypted_payload
# -32     32    hmac (SHA-256 по всему пакету до HMAC)

HEADER_FORMAT = "!4sB16sQI12sH"
HEADER_SIZE = struct.calcsize(HEADER_FORMAT)  # 47 bytes

# ── Обфускация ────────────────────────────────────────────────────
OBFUSCATION_MODES = ["none", "random_padding", "tls_mimicry"]
DEFAULT_OBFUSCATION = "random_padding"
MIN_PADDING = 0
MAX_PADDING = 256               # Максимальный padding в байтах

# ── TLS-мимикрия ──────────────────────────────────────────────────
# Первые байты имитируют TLS 1.3 ClientHello
TLS_CONTENT_TYPE = 0x16         # Handshake
TLS_VERSION_MAJOR = 0x03
TLS_VERSION_MINOR = 0x03        # TLS 1.2 record layer (как в TLS 1.3)

# ── Коды ошибок ───────────────────────────────────────────────────
class ErrorCode:
    OK = 0
    AUTH_FAILED = 1
    SESSION_EXPIRED = 2
    REPLAY_DETECTED = 3
    INVALID_PACKET = 4
    RATE_LIMITED = 5
    SERVER_FULL = 6
    VERSION_MISMATCH = 7


def generate_session_magic() -> bytes:
    """Генерирует случайные магические байты для сессии."""
    return os.urandom(MAGIC_SIZE)
