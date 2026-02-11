"""
ShadowTunnel Protocol — управление сессиями.

Реализует:
- 3-way handshake (INIT_HELLO → INIT_CHALLENGE → INIT_RESPONSE → INIT_CONFIRM)
- Anti-replay защита (скользящее окно)
- Ротация ключей
- Таймауты и keepalive
"""

import os
import time
import struct
import logging
from enum import Enum
from typing import Optional, Dict, Tuple
from dataclasses import dataclass, field

from .constants import (
    SESSION_ID_SIZE,
    REPLAY_WINDOW_SIZE,
    TIMESTAMP_TOLERANCE,
    KEY_ROTATION_INTERVAL,
    SESSION_TIMEOUT,
    KEEPALIVE_INTERVAL,
    CHALLENGE_SIZE,
    PacketType,
    ErrorCode,
    generate_session_magic,
)
from .crypto import ShadowCrypto, CryptoError
from .packet import ShadowPacket, PacketBuilder, PacketError

logger = logging.getLogger("shadowtunnel.session")


class SessionState(Enum):
    """Состояния сессии."""
    NEW = "new"
    HELLO_SENT = "hello_sent"
    CHALLENGE_SENT = "challenge_sent"
    RESPONSE_SENT = "response_sent"
    ESTABLISHED = "established"
    KEY_ROTATING = "key_rotating"
    DISCONNECTING = "disconnecting"
    CLOSED = "closed"


@dataclass
class ReplayWindow:
    """
    Скользящее окно anti-replay защиты.
    Отслеживает принятые sequence numbers.
    """
    _max_seq: int = 0
    _bitmap: int = 0  # Битовая карта для окна
    _window_size: int = REPLAY_WINDOW_SIZE

    def check_and_update(self, seq: int) -> bool:
        """
        Проверяет sequence number на replay.
        
        Returns:
            True если пакет принят (не replay), False если replay
        """
        if seq > self._max_seq:
            # Сдвигаем окно
            diff = seq - self._max_seq
            if diff < self._window_size:
                self._bitmap = (self._bitmap << diff) | 1
            else:
                self._bitmap = 1
            self._max_seq = seq
            return True
        
        # seq <= max_seq — проверяем в окне
        diff = self._max_seq - seq
        if diff >= self._window_size:
            return False  # Слишком старый

        bit = 1 << diff
        if self._bitmap & bit:
            return False  # Уже видели
        
        self._bitmap |= bit
        return True


@dataclass
class SessionInfo:
    """Информация о сессии."""
    session_id: bytes
    magic: bytes
    state: SessionState = SessionState.NEW
    crypto: ShadowCrypto = field(default_factory=ShadowCrypto)
    packet_builder: Optional[PacketBuilder] = None
    replay_window: ReplayWindow = field(default_factory=ReplayWindow)
    
    # Адрес удалённой стороны
    remote_addr: Optional[Tuple[str, int]] = None
    
    # Назначенный IP в туннеле (для клиента)
    tunnel_ip: Optional[str] = None
    
    # Временные метки
    created_at: float = field(default_factory=time.time)
    last_activity: float = field(default_factory=time.time)
    last_keepalive: float = field(default_factory=time.time)
    
    # Ротация ключей
    last_key_rotation: float = field(default_factory=time.time)
    rotation_counter: int = 0
    
    # Challenge для handshake
    challenge: Optional[bytes] = None
    
    # Статистика
    bytes_sent: int = 0
    bytes_received: int = 0
    packets_sent: int = 0
    packets_received: int = 0

    def __post_init__(self):
        if self.packet_builder is None:
            self.packet_builder = PacketBuilder(self.magic, self.session_id)

    def touch(self):
        """Обновляет время последней активности."""
        self.last_activity = time.time()

    def is_expired(self) -> bool:
        """Проверяет, истёк ли таймаут сессии."""
        return (time.time() - self.last_activity) > SESSION_TIMEOUT

    def needs_keepalive(self) -> bool:
        """Проверяет, нужно ли отправить keepalive."""
        return (time.time() - self.last_keepalive) > KEEPALIVE_INTERVAL

    def needs_key_rotation(self) -> bool:
        """Проверяет, нужна ли ротация ключей."""
        return (time.time() - self.last_key_rotation) > KEY_ROTATION_INTERVAL

    def check_timestamp(self, packet_timestamp_ms: int) -> bool:
        """Проверяет временную метку пакета для anti-replay."""
        current_ms = int(time.time() * 1000)
        diff_seconds = abs(current_ms - packet_timestamp_ms) / 1000
        return diff_seconds <= TIMESTAMP_TOLERANCE

    def update_stats(self, sent: int = 0, received: int = 0, pkt_sent: int = 0, pkt_recv: int = 0):
        """Обновляет статистику сессии."""
        self.bytes_sent += sent
        self.bytes_received += received
        self.packets_sent += pkt_sent
        self.packets_received += pkt_recv

    def to_dict(self) -> dict:
        """Возвращает информацию о сессии в виде словаря (для API)."""
        return {
            "session_id": self.session_id.hex(),
            "state": self.state.value,
            "remote_addr": f"{self.remote_addr[0]}:{self.remote_addr[1]}" if self.remote_addr else None,
            "tunnel_ip": self.tunnel_ip,
            "created_at": self.created_at,
            "last_activity": self.last_activity,
            "uptime_seconds": int(time.time() - self.created_at),
            "bytes_sent": self.bytes_sent,
            "bytes_received": self.bytes_received,
            "packets_sent": self.packets_sent,
            "packets_received": self.packets_received,
            "rotation_counter": self.rotation_counter,
        }


class SessionManager:
    """
    Менеджер сессий. Управляет жизненным циклом всех активных сессий.
    """

    def __init__(self, max_sessions: int = 256):
        self._sessions: Dict[bytes, SessionInfo] = {}
        self._addr_to_session: Dict[Tuple[str, int], bytes] = {}
        self._ip_to_session: Dict[str, bytes] = {}
        self._max_sessions = max_sessions

    def create_session(
        self,
        remote_addr: Tuple[str, int],
    ) -> SessionInfo:
        """Создаёт новую сессию."""
        if len(self._sessions) >= self._max_sessions:
            # Удаляем самую старую неактивную сессию
            self._cleanup_oldest()

        session_id = os.urandom(SESSION_ID_SIZE)
        magic = generate_session_magic()
        
        session = SessionInfo(
            session_id=session_id,
            magic=magic,
            remote_addr=remote_addr,
        )
        
        self._sessions[session_id] = session
        self._addr_to_session[remote_addr] = session_id
        
        logger.info(
            f"Session created: {session_id.hex()[:16]}... "
            f"from {remote_addr[0]}:{remote_addr[1]}"
        )
        return session

    def get_session(self, session_id: bytes) -> Optional[SessionInfo]:
        """Получает сессию по ID."""
        return self._sessions.get(session_id)

    def get_session_by_addr(self, addr: Tuple[str, int]) -> Optional[SessionInfo]:
        """Получает сессию по адресу."""
        sid = self._addr_to_session.get(addr)
        if sid:
            return self._sessions.get(sid)
        return None

    def get_session_by_tunnel_ip(self, ip: str) -> Optional[SessionInfo]:
        """Получает сессию по IP в туннеле."""
        sid = self._ip_to_session.get(ip)
        if sid:
            return self._sessions.get(sid)
        return None

    def assign_tunnel_ip(self, session_id: bytes, ip: str):
        """Назначает IP в туннеле для сессии."""
        session = self._sessions.get(session_id)
        if session:
            session.tunnel_ip = ip
            self._ip_to_session[ip] = session_id

    def remove_session(self, session_id: bytes):
        """Удаляет сессию."""
        session = self._sessions.pop(session_id, None)
        if session:
            if session.remote_addr:
                self._addr_to_session.pop(session.remote_addr, None)
            if session.tunnel_ip:
                self._ip_to_session.pop(session.tunnel_ip, None)
            session.crypto.clear_keys()
            logger.info(f"Session removed: {session_id.hex()[:16]}...")

    def cleanup_expired(self) -> int:
        """
        Удаляет все истёкшие сессии.
        
        Returns:
            Количество удалённых сессий
        """
        expired = [
            sid for sid, session in self._sessions.items()
            if session.is_expired() and session.state != SessionState.ESTABLISHED
        ]
        for sid in expired:
            self.remove_session(sid)
        
        # Для established — более длинный таймаут
        stale = [
            sid for sid, session in self._sessions.items()
            if (time.time() - session.last_activity) > SESSION_TIMEOUT * 2
        ]
        for sid in stale:
            self.remove_session(sid)
        
        total = len(expired) + len(stale)
        if total > 0:
            logger.info(f"Cleaned up {total} expired sessions")
        return total

    def get_all_sessions(self) -> list:
        """Возвращает информацию о всех сессиях (для API)."""
        return [s.to_dict() for s in self._sessions.values()]

    def get_active_count(self) -> int:
        """Количество активных (established) сессий."""
        return sum(
            1 for s in self._sessions.values()
            if s.state == SessionState.ESTABLISHED
        )

    def _cleanup_oldest(self):
        """Удаляет самую старую неактивную сессию."""
        if not self._sessions:
            return
        oldest_sid = min(
            self._sessions,
            key=lambda sid: self._sessions[sid].last_activity,
        )
        self.remove_session(oldest_sid)

    @property
    def total_sessions(self) -> int:
        return len(self._sessions)
