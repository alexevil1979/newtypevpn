"""
ShadowTunnel Windows Client — клиентский туннель.

Управляет:
- Подключением к серверу через UDP
- 3-way handshake
- Шифрованием/дешифрованием пакетов
- Keepalive и переподключением
- Ротацией ключей
"""

import os
import sys
import time
import socket
import struct
import logging
import threading
from typing import Optional, Callable
from enum import Enum

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from shared.crypto import ShadowCrypto, CryptoError
from shared.packet import ShadowPacket, PacketBuilder, PacketError
from shared.session import SessionInfo, SessionState, ReplayWindow
from shared.constants import (
    PacketType,
    X25519_KEY_SIZE,
    ED25519_SIG_SIZE,
    CHALLENGE_SIZE,
    AES_NONCE_SIZE,
    HMAC_SIZE,
    HEADER_SIZE,
    KEEPALIVE_INTERVAL,
    KEY_ROTATION_INTERVAL,
    RECONNECT_DELAY_BASE,
    RECONNECT_DELAY_MAX,
    generate_session_magic,
    SESSION_ID_SIZE,
)
try:
    from win_client.config import ClientConfig
except ImportError:
    from config import ClientConfig

logger = logging.getLogger("shadowtunnel.client")


class ConnectionState(Enum):
    DISCONNECTED = "disconnected"
    CONNECTING = "connecting"
    CONNECTED = "connected"
    RECONNECTING = "reconnecting"
    ERROR = "error"


class ClientTunnel:
    """
    Клиентский VPN-туннель.
    """

    def __init__(
        self,
        config: ClientConfig,
        on_state_change: Optional[Callable] = None,
        on_log: Optional[Callable] = None,
    ):
        self._config = config
        self._on_state_change = on_state_change
        self._on_log = on_log

        self._state = ConnectionState.DISCONNECTED
        self._socket: Optional[socket.socket] = None
        self._crypto = ShadowCrypto()
        self._session: Optional[SessionInfo] = None

        self._identity_key = None
        self._running = False
        self._recv_thread: Optional[threading.Thread] = None
        self._keepalive_thread: Optional[threading.Thread] = None

        self._reconnect_delay = RECONNECT_DELAY_BASE
        self._bytes_sent = 0
        self._bytes_received = 0

    @property
    def state(self) -> ConnectionState:
        return self._state

    @property
    def stats(self) -> dict:
        return {
            "bytes_sent": self._bytes_sent,
            "bytes_received": self._bytes_received,
            "state": self._state.value,
            "tunnel_ip": self._session.tunnel_ip if self._session else None,
        }

    def connect(self):
        """Инициирует подключение к серверу."""
        if self._state == ConnectionState.CONNECTED:
            return

        self._set_state(ConnectionState.CONNECTING)
        self._log("Подключение к серверу...")

        try:
            # Загружаем/генерируем ключи
            self._load_or_generate_keys()

            # Создаём UDP-сокет
            self._socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self._socket.settimeout(10)

            # Инициируем handshake
            success = self._perform_handshake()
            if not success:
                self._set_state(ConnectionState.ERROR)
                self._log("Ошибка handshake")
                return

            # Запускаем потоки
            self._running = True
            self._recv_thread = threading.Thread(target=self._recv_loop, daemon=True)
            self._recv_thread.start()
            self._keepalive_thread = threading.Thread(target=self._keepalive_loop, daemon=True)
            self._keepalive_thread.start()

            self._set_state(ConnectionState.CONNECTED)
            self._reconnect_delay = RECONNECT_DELAY_BASE
            self._log(f"Подключено! Tunnel IP: {self._session.tunnel_ip or 'N/A'}")

        except Exception as e:
            self._set_state(ConnectionState.ERROR)
            self._log(f"Ошибка подключения: {e}")
            if self._config.auto_reconnect:
                self._schedule_reconnect()

    def disconnect(self):
        """Отключается от сервера."""
        self._running = False
        self._log("Отключение...")

        if self._session and self._socket:
            try:
                pkt = self._session.packet_builder.build_disconnect()
                pkt_bytes = pkt.header_bytes + pkt.payload + pkt.padding
                pkt.hmac = self._session.crypto.compute_hmac(pkt_bytes)
                self._socket.sendto(
                    pkt.serialize(),
                    (self._config.server_addr, self._config.server_port),
                )
            except Exception:
                pass

        if self._socket:
            self._socket.close()
            self._socket = None

        self._session = None
        self._set_state(ConnectionState.DISCONNECTED)
        self._log("Отключено")

    def _perform_handshake(self) -> bool:
        """Выполняет 3-way handshake с сервером."""
        server_addr = (self._config.server_addr, self._config.server_port)

        # Создаём сессию
        session_id = os.urandom(SESSION_ID_SIZE)
        magic = generate_session_magic()
        self._session = SessionInfo(
            session_id=session_id,
            magic=magic,
        )
        self._session.crypto = self._crypto

        # Шаг 1: INIT_HELLO
        eph_priv, eph_pub = ShadowCrypto.generate_ephemeral_keypair()
        eph_pub_raw = ShadowCrypto.export_x25519_public(eph_pub)

        # Подписываем ephemeral key
        identity_pub_raw = ShadowCrypto.serialize_public_key(
            self._identity_key.public_key()
        )[:32]
        sig = ShadowCrypto.sign(self._identity_key, eph_pub_raw)

        hello_payload = eph_pub_raw + identity_pub_raw + sig

        hello_pkt = self._session.packet_builder.build_handshake_packet(
            PacketType.INIT_HELLO,
            hello_payload,
        )
        # HMAC не нужен для первого пакета (ключи ещё не установлены)
        hello_pkt.hmac = b"\x00" * HMAC_SIZE

        self._socket.sendto(hello_pkt.serialize(), server_addr)
        self._log("INIT_HELLO отправлен")

        # Шаг 2: Ожидаем INIT_CHALLENGE
        try:
            data, addr = self._socket.recvfrom(65535)
        except socket.timeout:
            self._log("Таймаут ожидания INIT_CHALLENGE")
            return False

        challenge_pkt = ShadowPacket.deserialize(data)
        if challenge_pkt.packet_type != PacketType.INIT_CHALLENGE:
            self._log("Неожиданный тип пакета вместо INIT_CHALLENGE")
            return False

        # Обновляем session_id и magic от сервера
        self._session.session_id = challenge_pkt.session_id
        self._session.magic = challenge_pkt.magic
        self._session.packet_builder = PacketBuilder(
            challenge_pkt.magic, challenge_pkt.session_id
        )

        # Парсим ответ: server_ephemeral_pub + nonce + encrypted
        payload = challenge_pkt.payload
        server_eph_pub_raw = payload[:X25519_KEY_SIZE]
        enc_nonce = payload[X25519_KEY_SIZE:X25519_KEY_SIZE + AES_NONCE_SIZE]
        encrypted_data = payload[X25519_KEY_SIZE + AES_NONCE_SIZE:]

        # ECDH
        server_eph_pub = ShadowCrypto.import_x25519_public(server_eph_pub_raw)
        self._crypto.perform_ecdh(eph_priv, server_eph_pub)

        # Дешифруем challenge
        decrypted = self._crypto.decrypt(
            enc_nonce,
            encrypted_data,
            associated_data=self._session.session_id,
        )

        challenge = decrypted[:CHALLENGE_SIZE]
        self._log("INIT_CHALLENGE получен, отправляю ответ...")

        # Шаг 3: INIT_RESPONSE
        challenge_sig = ShadowCrypto.sign(self._identity_key, challenge)
        response_plain = challenge_sig + challenge

        nonce, response_enc = self._crypto.encrypt(
            response_plain,
            associated_data=self._session.session_id,
        )

        response_pkt = self._session.packet_builder.build_handshake_packet(
            PacketType.INIT_RESPONSE,
            response_enc,
            nonce,
        )
        pkt_bytes = response_pkt.header_bytes + response_pkt.payload + response_pkt.padding
        response_pkt.hmac = self._crypto.compute_hmac(pkt_bytes)

        self._socket.sendto(response_pkt.serialize(), server_addr)

        # Ожидаем INIT_CONFIRM
        try:
            data, addr = self._socket.recvfrom(65535)
        except socket.timeout:
            self._log("Таймаут ожидания INIT_CONFIRM")
            return False

        confirm_pkt = ShadowPacket.deserialize(data, expected_magic=self._session.magic)
        if confirm_pkt.packet_type != PacketType.INIT_CONFIRM:
            self._log("Неожиданный тип пакета вместо INIT_CONFIRM")
            return False

        # Дешифруем подтверждение
        confirm_data = self._crypto.decrypt(
            confirm_pkt.nonce,
            confirm_pkt.payload,
            associated_data=self._session.session_id,
        )

        error_code = struct.unpack("!I", confirm_data[:4])[0]
        if error_code != 0:
            self._log(f"Сервер отклонил подключение: код {error_code}")
            return False

        # Извлекаем tunnel IP
        if len(confirm_data) > 4:
            self._session.tunnel_ip = confirm_data[4:].decode("utf-8")

        self._session.state = SessionState.ESTABLISHED
        self._session.replay_window = ReplayWindow()
        return True

    def _recv_loop(self):
        """Цикл приёма пакетов."""
        while self._running:
            try:
                if self._socket is None:
                    break
                self._socket.settimeout(1)
                data, addr = self._socket.recvfrom(65535)
                self._bytes_received += len(data)
                self._handle_received(data)
            except socket.timeout:
                continue
            except OSError:
                if self._running:
                    self._log("Соединение потеряно")
                    self._set_state(ConnectionState.ERROR)
                    if self._config.auto_reconnect:
                        self._schedule_reconnect()
                break
            except Exception as e:
                logger.error(f"Recv error: {e}")

    def _handle_received(self, data: bytes):
        """Обрабатывает полученный пакет."""
        if not self._session or len(data) < HEADER_SIZE + HMAC_SIZE:
            return

        try:
            pkt = ShadowPacket.deserialize(data, expected_magic=self._session.magic)

            if pkt.packet_type == PacketType.DATA:
                # Проверяем HMAC
                data_for_hmac = data[:-HMAC_SIZE]
                if not self._session.crypto.verify_hmac(data_for_hmac, pkt.hmac):
                    return

                # Anti-replay
                if not self._session.replay_window.check_and_update(pkt.sequence):
                    return

                # Дешифруем
                plaintext = self._session.crypto.decrypt(
                    pkt.nonce, pkt.payload,
                    associated_data=self._session.session_id,
                )
                # TODO: Записать в TUN/TAP интерфейс
                self._session.touch()

            elif pkt.packet_type == PacketType.KEEPALIVE:
                self._session.touch()

            elif pkt.packet_type == PacketType.KEY_ROTATE_ACK:
                self._session.touch()
                self._log("Ключи ротированы")

        except (PacketError, CryptoError) as e:
            logger.debug(f"Packet handling error: {e}")

    def _keepalive_loop(self):
        """Цикл отправки keepalive."""
        while self._running:
            time.sleep(self._config.keepalive_interval)
            if not self._running or not self._session:
                break
            if self._session.state != SessionState.ESTABLISHED:
                break
            try:
                pkt = self._session.packet_builder.build_keepalive()
                pkt_bytes = pkt.header_bytes + pkt.payload + pkt.padding
                pkt.hmac = self._session.crypto.compute_hmac(pkt_bytes)
                self._socket.sendto(
                    pkt.serialize(),
                    (self._config.server_addr, self._config.server_port),
                )

                # Проверяем необходимость ротации ключей
                if self._session.needs_key_rotation():
                    self._initiate_key_rotation()

            except Exception as e:
                logger.debug(f"Keepalive error: {e}")

    def _initiate_key_rotation(self):
        """Инициирует ротацию ключей."""
        if not self._session:
            return
        try:
            self._session.rotation_counter += 1
            self._session.crypto.derive_rotation_keys(
                self._session.crypto.session_key,
                self._session.rotation_counter,
            )
            self._session.last_key_rotation = time.time()
            self._log(f"Ротация ключей #{self._session.rotation_counter}")
        except CryptoError as e:
            logger.error(f"Key rotation failed: {e}")

    def _schedule_reconnect(self):
        """Планирует переподключение с экспоненциальным backoff."""
        def reconnect():
            time.sleep(self._reconnect_delay)
            self._reconnect_delay = min(
                self._reconnect_delay * 2,
                RECONNECT_DELAY_MAX,
            )
            if self._state != ConnectionState.CONNECTED:
                self._log(f"Попытка переподключения...")
                self.connect()

        threading.Thread(target=reconnect, daemon=True).start()

    def _load_or_generate_keys(self):
        """Загружает или генерирует ключи клиента."""
        key_path = self._config.private_key_file
        if key_path and os.path.exists(key_path):
            with open(key_path, "rb") as f:
                self._identity_key = ShadowCrypto.deserialize_private_key(f.read())
        else:
            self._identity_key, pub = ShadowCrypto.generate_identity_keypair()
            if key_path:
                os.makedirs(os.path.dirname(key_path), exist_ok=True)
                with open(key_path, "wb") as f:
                    f.write(ShadowCrypto.serialize_private_key(self._identity_key))
            self._log("Сгенерированы новые ключи")

    def _set_state(self, state: ConnectionState):
        """Обновляет состояние и уведомляет GUI."""
        self._state = state
        if self._on_state_change:
            self._on_state_change(state)

    def _log(self, message: str):
        """Отправляет сообщение в лог GUI."""
        logger.info(message)
        if self._on_log:
            self._on_log(message)
