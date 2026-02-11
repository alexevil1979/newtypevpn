"""
ShadowTunnel Server — обработка 3-way handshake.

Протокол рукопожатия:
1. Client → Server: INIT_HELLO  (client_ephemeral_pub + client_identity_pub)
2. Server → Client: INIT_CHALLENGE (server_ephemeral_pub + challenge + encrypted_data)
3. Client → Server: INIT_RESPONSE (signed_challenge + encrypted_response)
4. Server → Client: INIT_CONFIRM  (session_params)

На шаге 2 уже выполняется ECDH и устанавливается шифрование.
"""

import os
import struct
import time
import logging
from typing import Tuple, Optional

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)

import sys, pathlib
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2]))

from shared.crypto import ShadowCrypto, CryptoError
from shared.packet import ShadowPacket, PacketBuilder
from shared.session import SessionInfo, SessionState, SessionManager
from shared.constants import (
    PacketType,
    CHALLENGE_SIZE,
    X25519_KEY_SIZE,
    ED25519_SIG_SIZE,
    AES_NONCE_SIZE,
    generate_session_magic,
)

logger = logging.getLogger("shadowtunnel.handshake")


class ServerHandshake:
    """
    Обработчик серверного рукопожатия.
    Управляет 3-way handshake и установкой сессий.
    """

    def __init__(
        self,
        server_identity_key: Ed25519PrivateKey,
        session_manager: SessionManager,
        authorized_keys: dict,
    ):
        self._identity_key = server_identity_key
        self._identity_pub = server_identity_key.public_key()
        self._session_manager = session_manager
        self._authorized_keys = authorized_keys  # name -> Ed25519PublicKey

    def handle_init_hello(
        self,
        data: bytes,
        remote_addr: Tuple[str, int],
    ) -> Optional[Tuple[bytes, SessionInfo]]:
        """
        Обрабатывает INIT_HELLO от клиента.
        
        Payload клиента:
        - client_ephemeral_pub (32 bytes, X25519 raw)
        - client_identity_pub (44 bytes, Ed25519 compressed)
        - client_signature (64 bytes, подпись ephemeral_pub)
        
        Returns:
            (response_bytes, session) или None при ошибке
        """
        try:
            if len(data) < X25519_KEY_SIZE + 32 + ED25519_SIG_SIZE:
                logger.warning(f"INIT_HELLO too short from {remote_addr}")
                return None

            # Парсим payload
            offset = 0
            client_eph_pub_raw = data[offset:offset + X25519_KEY_SIZE]
            offset += X25519_KEY_SIZE

            client_id_pub_raw = data[offset:offset + 32]
            offset += 32

            client_signature = data[offset:offset + ED25519_SIG_SIZE]
            offset += ED25519_SIG_SIZE

            # Импортируем ключи клиента
            client_eph_pub = ShadowCrypto.import_x25519_public(client_eph_pub_raw)

            # Проверяем, авторизован ли клиент
            client_name = self._find_authorized_client(client_id_pub_raw)
            if client_name is None:
                logger.warning(f"Unauthorized client from {remote_addr}")
                return None

            # Создаём сессию
            session = self._session_manager.create_session(remote_addr)
            session.state = SessionState.CHALLENGE_SENT

            # Генерируем серверный эфемерный ключ
            server_eph_priv, server_eph_pub = ShadowCrypto.generate_ephemeral_keypair()
            server_eph_pub_raw = ShadowCrypto.export_x25519_public(server_eph_pub)

            # Выполняем ECDH
            session.crypto.perform_ecdh(server_eph_priv, client_eph_pub)

            # Генерируем challenge
            challenge = ShadowCrypto.generate_challenge()
            session.challenge = challenge

            # Собираем payload ответа
            # server_ephemeral_pub (32) + challenge (32), зашифрованные данные
            plain_response = server_eph_pub_raw + challenge

            # Подписываем server_eph_pub
            server_sig = ShadowCrypto.sign(self._identity_key, server_eph_pub_raw + challenge)

            # Шифруем challenge + подпись
            nonce, encrypted = session.crypto.encrypt(
                challenge + server_sig,
                associated_data=session.session_id,
            )

            # Формируем финальный payload
            response_payload = server_eph_pub_raw + nonce + encrypted

            # Создаём пакет
            packet = session.packet_builder.build_handshake_packet(
                PacketType.INIT_CHALLENGE,
                response_payload,
                nonce,
            )

            # Вычисляем HMAC
            packet_bytes = packet.header_bytes + packet.payload + packet.padding
            packet.hmac = session.crypto.compute_hmac(packet_bytes)

            logger.info(
                f"INIT_CHALLENGE sent to {remote_addr} "
                f"(session: {session.session_id.hex()[:16]}...)"
            )
            return packet.serialize(), session

        except (CryptoError, Exception) as e:
            logger.error(f"Error in INIT_HELLO handler: {e}")
            return None

    def handle_init_response(
        self,
        packet: ShadowPacket,
        session: SessionInfo,
    ) -> Optional[bytes]:
        """
        Обрабатывает INIT_RESPONSE от клиента.
        
        Payload:
        - signed_challenge (64 bytes)
        - encrypted response data
        
        Returns:
            INIT_CONFIRM bytes или None при ошибке
        """
        try:
            if session.state != SessionState.CHALLENGE_SENT:
                logger.warning("INIT_RESPONSE in wrong state")
                return None

            # Дешифруем payload
            plaintext = session.crypto.decrypt(
                packet.nonce,
                packet.payload,
                associated_data=session.session_id,
            )

            if len(plaintext) < ED25519_SIG_SIZE + CHALLENGE_SIZE:
                logger.warning("INIT_RESPONSE payload too short")
                return None

            client_challenge_sig = plaintext[:ED25519_SIG_SIZE]
            returned_challenge = plaintext[ED25519_SIG_SIZE:ED25519_SIG_SIZE + CHALLENGE_SIZE]

            # Проверяем challenge
            if returned_challenge != session.challenge:
                logger.warning("Challenge mismatch")
                return None

            # Сессия установлена
            session.state = SessionState.ESTABLISHED
            session.touch()

            # Формируем INIT_CONFIRM
            confirm_data = struct.pack("!I", 0)  # ErrorCode.OK
            if session.tunnel_ip:
                confirm_data += session.tunnel_ip.encode("utf-8")

            nonce, encrypted_confirm = session.crypto.encrypt(
                confirm_data,
                associated_data=session.session_id,
            )

            confirm_packet = session.packet_builder.build_handshake_packet(
                PacketType.INIT_CONFIRM,
                encrypted_confirm,
                nonce,
            )

            pkt_bytes = confirm_packet.header_bytes + confirm_packet.payload + confirm_packet.padding
            confirm_packet.hmac = session.crypto.compute_hmac(pkt_bytes)

            logger.info(
                f"Session ESTABLISHED: {session.session_id.hex()[:16]}... "
                f"tunnel_ip={session.tunnel_ip}"
            )
            return confirm_packet.serialize()

        except (CryptoError, Exception) as e:
            logger.error(f"Error in INIT_RESPONSE handler: {e}")
            return None

    def _find_authorized_client(self, pub_key_raw: bytes) -> Optional[str]:
        """Ищет авторизованного клиента по публичному ключу."""
        for name, key_data in self._authorized_keys.items():
            if key_data == pub_key_raw:
                return name
        # Если список пуст — разрешаем всех (dev mode)
        if not self._authorized_keys:
            return "anonymous"
        return None
