"""
ShadowTunnel Server — обработчик входящих пакетов.
"""

import logging
import time
from typing import Optional, Tuple

import sys, pathlib
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2]))

from shared.crypto import ShadowCrypto, CryptoError
from shared.packet import ShadowPacket, PacketError
from shared.session import SessionInfo, SessionState
from shared.constants import PacketType, HMAC_SIZE, HEADER_SIZE

logger = logging.getLogger("shadowtunnel.handler")


class PacketHandler:
    """
    Обработчик пакетов данных.
    Отвечает за дешифрование, проверку целостности и anti-replay.
    """

    def process_data_packet(
        self,
        raw_data: bytes,
        session: SessionInfo,
    ) -> Optional[bytes]:
        """
        Обрабатывает зашифрованный пакет данных.
        
        Returns:
            Расшифрованный payload (IP-пакет) или None при ошибке
        """
        try:
            # Десериализуем
            packet = ShadowPacket.deserialize(raw_data, expected_magic=session.magic)

            # Проверяем HMAC
            data_for_hmac = raw_data[:-HMAC_SIZE]
            if not session.crypto.verify_hmac(data_for_hmac, packet.hmac):
                logger.warning(
                    f"HMAC verification failed for session {session.session_id.hex()[:16]}"
                )
                return None

            # Проверяем timestamp
            if not session.check_timestamp(packet.timestamp):
                logger.warning(
                    f"Timestamp out of range for session {session.session_id.hex()[:16]}"
                )
                return None

            # Anti-replay
            if not session.replay_window.check_and_update(packet.sequence):
                logger.warning(
                    f"Replay detected for session {session.session_id.hex()[:16]}, "
                    f"seq={packet.sequence}"
                )
                return None

            # Дешифруем payload
            plaintext = session.crypto.decrypt(
                packet.nonce,
                packet.payload,
                associated_data=session.session_id,
            )

            # Обновляем статистику
            session.touch()
            session.update_stats(received=len(raw_data), pkt_recv=1)

            return plaintext

        except PacketError as e:
            logger.debug(f"Packet parse error: {e}")
            return None
        except CryptoError as e:
            logger.debug(f"Crypto error: {e}")
            return None

    def build_data_packet(
        self,
        plaintext: bytes,
        session: SessionInfo,
    ) -> Optional[bytes]:
        """
        Создаёт зашифрованный пакет данных для отправки.
        
        Args:
            plaintext: IP-пакет для отправки через туннель
            session: информация о сессии
            
        Returns:
            Сериализованный зашифрованный пакет
        """
        try:
            # Шифруем
            nonce, encrypted = session.crypto.encrypt(
                plaintext,
                associated_data=session.session_id,
            )

            # Создаём пакет
            packet = session.packet_builder.build_data_packet(encrypted, nonce)

            # Вычисляем HMAC
            pkt_bytes = packet.header_bytes + packet.payload + packet.padding
            packet.hmac = session.crypto.compute_hmac(pkt_bytes)

            # Обновляем статистику
            serialized = packet.serialize()
            session.update_stats(sent=len(serialized), pkt_sent=1)

            return serialized

        except CryptoError as e:
            logger.error(f"Error building data packet: {e}")
            return None

    def handle_keepalive(self, session: SessionInfo) -> bytes:
        """Обрабатывает keepalive и создаёт ответ."""
        session.touch()
        session.last_keepalive = time.time()

        packet = session.packet_builder.build_keepalive()
        pkt_bytes = packet.header_bytes + packet.payload + packet.padding
        packet.hmac = session.crypto.compute_hmac(pkt_bytes)

        return packet.serialize()

    def handle_key_rotation(
        self,
        raw_data: bytes,
        session: SessionInfo,
    ) -> Optional[bytes]:
        """
        Обрабатывает запрос ротации ключей.
        
        Генерирует новые ключи и отправляет подтверждение.
        """
        try:
            session.rotation_counter += 1
            session.crypto.derive_rotation_keys(
                session.crypto.session_key,
                session.rotation_counter,
            )
            session.last_key_rotation = time.time()
            session.state = SessionState.ESTABLISHED

            # Отправляем ACK
            ack_data = session.rotation_counter.to_bytes(4, "big")
            nonce, encrypted = session.crypto.encrypt(
                ack_data,
                associated_data=session.session_id,
            )

            packet = session.packet_builder.build_handshake_packet(
                PacketType.KEY_ROTATE_ACK,
                encrypted,
                nonce,
            )
            pkt_bytes = packet.header_bytes + packet.payload + packet.padding
            packet.hmac = session.crypto.compute_hmac(pkt_bytes)

            logger.info(
                f"Key rotation #{session.rotation_counter} for "
                f"session {session.session_id.hex()[:16]}"
            )
            return packet.serialize()

        except CryptoError as e:
            logger.error(f"Key rotation error: {e}")
            return None
