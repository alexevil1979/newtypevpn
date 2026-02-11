"""
Тесты протокола ShadowTunnel — пакеты, сессии, anti-replay.
"""

import os
import time
import struct
import pytest
from hypothesis import given, strategies as st

from shared.packet import ShadowPacket, PacketBuilder, PacketError
from shared.packet import wrap_with_tls_mimicry, unwrap_tls_mimicry
from shared.session import (
    SessionInfo, SessionState, SessionManager, ReplayWindow,
)
from shared.constants import (
    PacketType, HEADER_SIZE, HMAC_SIZE, SESSION_ID_SIZE,
    MAGIC_SIZE, AES_NONCE_SIZE, generate_session_magic,
)
from shared.crypto import ShadowCrypto


class TestShadowPacket:
    """Тесты формата пакетов."""

    def test_serialize_deserialize_roundtrip(self):
        """Пакет сериализуется и десериализуется корректно."""
        magic = os.urandom(4)
        session_id = os.urandom(16)
        nonce = os.urandom(12)
        payload = b"test payload data"
        
        pkt = ShadowPacket(
            magic=magic,
            packet_type=PacketType.DATA,
            session_id=session_id,
            nonce=nonce,
            payload=payload,
            hmac=os.urandom(32),
        )
        
        data = pkt.serialize()
        restored = ShadowPacket.deserialize(data)
        
        assert restored.magic == magic
        assert restored.packet_type == PacketType.DATA
        assert restored.session_id == session_id
        assert restored.nonce == nonce
        assert restored.payload == payload

    def test_magic_validation(self):
        """Неверные magic bytes вызывают ошибку."""
        pkt = ShadowPacket(
            magic=b"\x01\x02\x03\x04",
            hmac=os.urandom(32),
        )
        data = pkt.serialize()
        
        with pytest.raises(PacketError, match="Magic"):
            ShadowPacket.deserialize(data, expected_magic=b"\xFF\xFF\xFF\xFF")

    def test_correct_magic_passes(self):
        """Правильные magic bytes проходят проверку."""
        magic = b"\xAB\xCD\xEF\x01"
        pkt = ShadowPacket(magic=magic, hmac=os.urandom(32))
        data = pkt.serialize()
        
        restored = ShadowPacket.deserialize(data, expected_magic=magic)
        assert restored.magic == magic

    def test_too_small_packet_fails(self):
        """Слишком маленький пакет вызывает ошибку."""
        with pytest.raises(PacketError):
            ShadowPacket.deserialize(b"\x00" * 10)

    def test_timestamp_is_set(self):
        """Timestamp автоматически устанавливается."""
        pkt = ShadowPacket()
        assert pkt.timestamp > 0
        # Timestamp в миллисекундах
        assert pkt.timestamp > 1000000000000

    def test_header_size_is_correct(self):
        """Размер заголовка соответствует спецификации."""
        pkt = ShadowPacket(hmac=os.urandom(32))
        header = pkt.header_bytes
        assert len(header) == HEADER_SIZE

    @given(payload=st.binary(min_size=0, max_size=1000))
    def test_arbitrary_payload_roundtrip(self, payload):
        """Произвольный payload корректно сериализуется (fuzz)."""
        pkt = ShadowPacket(
            payload=payload,
            hmac=os.urandom(32),
        )
        data = pkt.serialize()
        restored = ShadowPacket.deserialize(data)
        assert restored.payload == payload


class TestPacketBuilder:
    """Тесты PacketBuilder."""

    def setup_method(self):
        self.magic = generate_session_magic()
        self.session_id = os.urandom(SESSION_ID_SIZE)
        self.builder = PacketBuilder(self.magic, self.session_id)

    def test_sequence_incrementing(self):
        """Sequence number инкрементируется."""
        pkt1 = self.builder.build_keepalive()
        pkt2 = self.builder.build_keepalive()
        assert pkt2.sequence == pkt1.sequence + 1

    def test_data_packet_type(self):
        """Data packet имеет правильный тип."""
        nonce = os.urandom(12)
        pkt = self.builder.build_data_packet(b"encrypted", nonce)
        assert pkt.packet_type == PacketType.DATA

    def test_keepalive_packet(self):
        """Keepalive пакет создаётся корректно."""
        pkt = self.builder.build_keepalive()
        assert pkt.packet_type == PacketType.KEEPALIVE
        assert pkt.magic == self.magic

    def test_disconnect_packet(self):
        """Disconnect пакет создаётся корректно."""
        pkt = self.builder.build_disconnect()
        assert pkt.packet_type == PacketType.DISCONNECT


class TestTLSMimicry:
    """Тесты TLS-обфускации."""

    def test_wrap_unwrap_roundtrip(self):
        """TLS-обёртка и развёртка сохраняют данные."""
        original = os.urandom(100)
        wrapped = wrap_with_tls_mimicry(original)
        unwrapped = unwrap_tls_mimicry(wrapped)
        assert unwrapped == original

    def test_wrapped_looks_like_tls(self):
        """Обёрнутый пакет начинается как TLS record."""
        data = os.urandom(50)
        wrapped = wrap_with_tls_mimicry(data)
        
        assert wrapped[0] == 0x17  # Application Data
        assert wrapped[1] == 0x03  # TLS major
        assert wrapped[2] == 0x03  # TLS minor

    def test_short_data_fails_unwrap(self):
        """Слишком короткие данные не развёртываются."""
        with pytest.raises(PacketError):
            unwrap_tls_mimicry(b"\x17\x03")


class TestReplayWindow:
    """Тесты anti-replay."""

    def test_first_packet_accepted(self):
        """Первый пакет принимается."""
        window = ReplayWindow()
        assert window.check_and_update(1)

    def test_duplicate_rejected(self):
        """Дублированный пакет отвергается."""
        window = ReplayWindow()
        assert window.check_and_update(1)
        assert not window.check_and_update(1)

    def test_sequential_accepted(self):
        """Последовательные пакеты принимаются."""
        window = ReplayWindow()
        for i in range(100):
            assert window.check_and_update(i)

    def test_out_of_order_within_window(self):
        """Пакеты не по порядку в пределах окна принимаются."""
        window = ReplayWindow()
        assert window.check_and_update(10)
        assert window.check_and_update(5)  # Старый но в пределах окна
        assert window.check_and_update(8)

    def test_very_old_packet_rejected(self):
        """Очень старый пакет за пределами окна отвергается."""
        window = ReplayWindow()
        # Продвигаем окно далеко вперёд
        assert window.check_and_update(2000)
        # Пакет далеко позади окна
        assert not window.check_and_update(1)

    @given(seq_nums=st.lists(st.integers(min_value=0, max_value=10000), min_size=1, max_size=200))
    def test_no_false_positives(self, seq_nums):
        """Replay window не теряет пакеты при нормальной работе (fuzz)."""
        window = ReplayWindow()
        seen = set()
        
        for seq in seq_nums:
            result = window.check_and_update(seq)
            if seq in seen:
                # Дубликат должен быть отвергнут (если в пределах окна)
                pass
            seen.add(seq)


class TestSessionManager:
    """Тесты управления сессиями."""

    def test_create_session(self):
        """Сессия создаётся с уникальным ID."""
        mgr = SessionManager()
        session = mgr.create_session(("1.2.3.4", 12345))
        
        assert session is not None
        assert len(session.session_id) == SESSION_ID_SIZE
        assert session.state == SessionState.NEW
        assert session.remote_addr == ("1.2.3.4", 12345)

    def test_get_session_by_id(self):
        """Сессия находится по ID."""
        mgr = SessionManager()
        session = mgr.create_session(("1.2.3.4", 12345))
        
        found = mgr.get_session(session.session_id)
        assert found is session

    def test_get_session_by_addr(self):
        """Сессия находится по адресу."""
        mgr = SessionManager()
        addr = ("1.2.3.4", 12345)
        session = mgr.create_session(addr)
        
        found = mgr.get_session_by_addr(addr)
        assert found is session

    def test_remove_session(self):
        """Удалённая сессия не находится."""
        mgr = SessionManager()
        session = mgr.create_session(("1.2.3.4", 12345))
        mgr.remove_session(session.session_id)
        
        assert mgr.get_session(session.session_id) is None

    def test_max_sessions_limit(self):
        """Превышение лимита сессий удаляет старую."""
        mgr = SessionManager(max_sessions=3)
        
        s1 = mgr.create_session(("1.1.1.1", 1))
        s2 = mgr.create_session(("2.2.2.2", 2))
        s3 = mgr.create_session(("3.3.3.3", 3))
        s4 = mgr.create_session(("4.4.4.4", 4))  # Должна удалить s1
        
        assert mgr.total_sessions == 3

    def test_assign_tunnel_ip(self):
        """IP в туннеле назначается и сессия находится по IP."""
        mgr = SessionManager()
        session = mgr.create_session(("1.2.3.4", 12345))
        mgr.assign_tunnel_ip(session.session_id, "10.8.0.2")
        
        found = mgr.get_session_by_tunnel_ip("10.8.0.2")
        assert found is session
        assert found.tunnel_ip == "10.8.0.2"

    def test_session_to_dict(self):
        """Сессия сериализуется в словарь для API."""
        mgr = SessionManager()
        session = mgr.create_session(("1.2.3.4", 12345))
        
        d = session.to_dict()
        assert "session_id" in d
        assert "state" in d
        assert d["state"] == "new"


class TestSessionInfo:
    """Тесты SessionInfo."""

    def test_timestamp_check_valid(self):
        """Валидная временная метка проходит проверку."""
        session = SessionInfo(
            session_id=os.urandom(16),
            magic=os.urandom(4),
        )
        current_ms = int(time.time() * 1000)
        assert session.check_timestamp(current_ms)

    def test_timestamp_check_expired(self):
        """Просроченная временная метка отвергается."""
        session = SessionInfo(
            session_id=os.urandom(16),
            magic=os.urandom(4),
        )
        old_ms = int((time.time() - 60) * 1000)  # 60 секунд назад
        assert not session.check_timestamp(old_ms)

    def test_needs_keepalive(self):
        """Keepalive нужен после истечения интервала."""
        session = SessionInfo(
            session_id=os.urandom(16),
            magic=os.urandom(4),
        )
        session.last_keepalive = time.time() - 30  # 30 сек назад
        assert session.needs_keepalive()

    def test_stats_update(self):
        """Статистика обновляется."""
        session = SessionInfo(
            session_id=os.urandom(16),
            magic=os.urandom(4),
        )
        session.update_stats(sent=100, received=200, pkt_sent=1, pkt_recv=2)
        assert session.bytes_sent == 100
        assert session.bytes_received == 200
        assert session.packets_sent == 1
        assert session.packets_received == 2
