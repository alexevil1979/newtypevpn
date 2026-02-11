"""
ShadowTunnel Protocol — формат пакетов и сериализация.

Структура пакета:
┌─────────────────────────────────────────────────────────┐
│  Magic (4B)  │  Type (1B)  │  Session ID (16B)          │
│  Timestamp (8B)  │  Sequence (4B)  │  Nonce (12B)       │
│  Payload Length (2B)  │  Encrypted Payload (variable)    │
│  Padding (variable)  │  HMAC-SHA256 (32B)               │
└─────────────────────────────────────────────────────────┘
"""

import os
import struct
import time
from dataclasses import dataclass, field
from typing import Optional, Tuple

from .constants import (
    HEADER_FORMAT,
    HEADER_SIZE,
    HMAC_SIZE,
    AES_NONCE_SIZE,
    SESSION_ID_SIZE,
    MAGIC_SIZE,
    MAX_PACKET_SIZE,
    MIN_PACKET_SIZE,
    MAX_PAYLOAD_SIZE,
    MIN_PADDING,
    MAX_PADDING,
    PacketType,
    TLS_CONTENT_TYPE,
    TLS_VERSION_MAJOR,
    TLS_VERSION_MINOR,
)


class PacketError(Exception):
    """Ошибка при работе с пакетами."""
    pass


@dataclass
class ShadowPacket:
    """
    Представление пакета протокола ShadowTunnel.
    """
    magic: bytes = field(default_factory=lambda: os.urandom(MAGIC_SIZE))
    packet_type: int = PacketType.DATA
    session_id: bytes = field(default_factory=lambda: b"\x00" * SESSION_ID_SIZE)
    timestamp: int = 0
    sequence: int = 0
    nonce: bytes = field(default_factory=lambda: b"\x00" * AES_NONCE_SIZE)
    payload: bytes = b""
    padding: bytes = b""
    hmac: bytes = b""

    def __post_init__(self):
        if self.timestamp == 0:
            self.timestamp = int(time.time() * 1000)  # Миллисекунды

    @property
    def header_bytes(self) -> bytes:
        """Сериализует заголовок пакета (без payload и HMAC)."""
        return struct.pack(
            HEADER_FORMAT,
            self.magic,
            self.packet_type,
            self.session_id,
            self.timestamp,
            self.sequence,
            self.nonce,
            len(self.payload),
        )

    def serialize(self) -> bytes:
        """
        Сериализует полный пакет в байты для отправки.
        
        Returns:
            bytes: сериализованный пакет с HMAC в конце
        """
        header = self.header_bytes
        body = header + self.payload + self.padding
        return body + self.hmac

    @classmethod
    def deserialize(cls, data: bytes, expected_magic: Optional[bytes] = None) -> "ShadowPacket":
        """
        Десериализует пакет из сырых байтов.
        
        Args:
            data: сырые байты пакета
            expected_magic: ожидаемые магические байты (None = не проверять)
            
        Returns:
            ShadowPacket: распарсенный пакет
            
        Raises:
            PacketError: при ошибке парсинга
        """
        if len(data) < HEADER_SIZE + HMAC_SIZE:
            raise PacketError(
                f"Packet too small: {len(data)} bytes "
                f"(min: {HEADER_SIZE + HMAC_SIZE})"
            )

        # Извлекаем HMAC (последние 32 байта)
        packet_hmac = data[-HMAC_SIZE:]
        data_without_hmac = data[:-HMAC_SIZE]

        # Парсим заголовок
        try:
            (
                magic,
                packet_type,
                session_id,
                timestamp,
                sequence,
                nonce,
                payload_length,
            ) = struct.unpack(HEADER_FORMAT, data_without_hmac[:HEADER_SIZE])
        except struct.error as e:
            raise PacketError(f"Header parse error: {e}")

        # Проверяем magic если задан
        if expected_magic is not None and magic != expected_magic:
            raise PacketError("Magic bytes mismatch")

        # Извлекаем payload
        payload_start = HEADER_SIZE
        payload_end = payload_start + payload_length

        if payload_end > len(data_without_hmac):
            raise PacketError(
                f"Payload exceeds packet bounds: need {payload_end} bytes, "
                f"have {len(data_without_hmac)}"
            )

        payload = data_without_hmac[payload_start:payload_end]

        # Остальное — padding
        padding = data_without_hmac[payload_end:]

        return cls(
            magic=magic,
            packet_type=packet_type,
            session_id=session_id,
            timestamp=timestamp,
            sequence=sequence,
            nonce=nonce,
            payload=payload,
            padding=padding,
            hmac=packet_hmac,
        )


class PacketBuilder:
    """
    Билдер для создания пакетов с обфускацией.
    """

    def __init__(
        self,
        session_magic: bytes,
        session_id: bytes,
        obfuscation: str = "random_padding",
    ):
        self.session_magic = session_magic
        self.session_id = session_id
        self.obfuscation = obfuscation
        self._sequence = 0

    def next_sequence(self) -> int:
        """Возвращает следующий номер последовательности."""
        seq = self._sequence
        self._sequence = (self._sequence + 1) % (2**32)
        return seq

    def build_data_packet(
        self,
        encrypted_payload: bytes,
        nonce: bytes,
    ) -> ShadowPacket:
        """Создаёт пакет данных."""
        padding = self._generate_padding()
        return ShadowPacket(
            magic=self.session_magic,
            packet_type=PacketType.DATA,
            session_id=self.session_id,
            sequence=self.next_sequence(),
            nonce=nonce,
            payload=encrypted_payload,
            padding=padding,
        )

    def build_handshake_packet(
        self,
        packet_type: int,
        payload: bytes,
        nonce: bytes = b"\x00" * AES_NONCE_SIZE,
    ) -> ShadowPacket:
        """Создаёт пакет рукопожатия."""
        return ShadowPacket(
            magic=self.session_magic,
            packet_type=packet_type,
            session_id=self.session_id,
            sequence=self.next_sequence(),
            nonce=nonce,
            payload=payload,
        )

    def build_keepalive(self) -> ShadowPacket:
        """Создаёт keepalive-пакет."""
        return ShadowPacket(
            magic=self.session_magic,
            packet_type=PacketType.KEEPALIVE,
            session_id=self.session_id,
            sequence=self.next_sequence(),
        )

    def build_disconnect(self) -> ShadowPacket:
        """Создаёт пакет отключения."""
        return ShadowPacket(
            magic=self.session_magic,
            packet_type=PacketType.DISCONNECT,
            session_id=self.session_id,
            sequence=self.next_sequence(),
        )

    def build_key_rotate(self, payload: bytes, nonce: bytes) -> ShadowPacket:
        """Создаёт пакет запроса ротации ключей."""
        return ShadowPacket(
            magic=self.session_magic,
            packet_type=PacketType.KEY_ROTATE,
            session_id=self.session_id,
            sequence=self.next_sequence(),
            nonce=nonce,
            payload=payload,
        )

    def _generate_padding(self) -> bytes:
        """Генерирует обфусцирующий padding."""
        if self.obfuscation == "none":
            return b""
        elif self.obfuscation == "random_padding":
            pad_len = int.from_bytes(os.urandom(1), "big") % (MAX_PADDING + 1)
            return os.urandom(pad_len)
        elif self.obfuscation == "tls_mimicry":
            return self._tls_mimicry_padding()
        return b""

    def _tls_mimicry_padding(self) -> bytes:
        """
        Генерирует padding, имитирующий TLS-трафик.
        Добавляет структуру, похожую на TLS record.
        """
        # Имитация TLS record header
        tls_header = bytes([
            TLS_CONTENT_TYPE,
            TLS_VERSION_MAJOR,
            TLS_VERSION_MINOR,
        ])
        # Случайный payload имитирующий зашифрованные данные TLS
        fake_tls_len = int.from_bytes(os.urandom(1), "big") % 128 + 32
        fake_tls_data = os.urandom(fake_tls_len)
        length_bytes = struct.pack("!H", len(fake_tls_data))
        return tls_header + length_bytes + fake_tls_data


def wrap_with_tls_mimicry(packet_bytes: bytes) -> bytes:
    """
    Оборачивает пакет в TLS-подобную обёртку для обхода DPI.
    
    Выглядит как TLS 1.3 Application Data record.
    """
    # TLS record: ContentType(1) + Version(2) + Length(2) + Data
    tls_wrapper = bytes([
        0x17,  # Application Data
        TLS_VERSION_MAJOR,
        TLS_VERSION_MINOR,
    ])
    tls_wrapper += struct.pack("!H", len(packet_bytes))
    return tls_wrapper + packet_bytes


def unwrap_tls_mimicry(data: bytes) -> bytes:
    """Снимает TLS-обёртку с пакета."""
    if len(data) < 5:
        raise PacketError("TLS wrapper too short")
    if data[0] != 0x17:
        raise PacketError("Not a TLS Application Data record")
    length = struct.unpack("!H", data[3:5])[0]
    if len(data) < 5 + length:
        raise PacketError("TLS record truncated")
    return data[5:5 + length]
