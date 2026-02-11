"""
ShadowTunnel Server — UDP-туннель.

Главный цикл обработки пакетов:
- Приём UDP-пакетов от клиентов
- Маршрутизация через TUN-интерфейс
- Обратная доставка ответов клиентам
"""

import asyncio
import logging
import time
from typing import Dict, Optional, Tuple

import sys, pathlib
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from shared.packet import ShadowPacket, PacketError
from shared.session import SessionInfo, SessionState, SessionManager
from shared.constants import PacketType, HMAC_SIZE, HEADER_SIZE
from server.protocol.handshake import ServerHandshake
from server.protocol.handler import PacketHandler
from server.nat import TunInterface, NATManager, IPPool, extract_dst_ip

logger = logging.getLogger("shadowtunnel.tunnel")


class ShadowTunnelProtocol(asyncio.DatagramProtocol):
    """
    Asyncio UDP-протокол для ShadowTunnel сервера.
    """

    def __init__(
        self,
        session_manager: SessionManager,
        handshake: ServerHandshake,
        packet_handler: PacketHandler,
        ip_pool: IPPool,
        tun: TunInterface,
    ):
        self._session_mgr = session_manager
        self._handshake = handshake
        self._pkt_handler = packet_handler
        self._ip_pool = ip_pool
        self._tun = tun
        self._transport: Optional[asyncio.DatagramTransport] = None

    def connection_made(self, transport: asyncio.DatagramTransport):
        self._transport = transport
        logger.info("UDP transport ready")

    def datagram_received(self, data: bytes, addr: Tuple[str, int]):
        """Обрабатывает входящий UDP-пакет."""
        if len(data) < HEADER_SIZE + HMAC_SIZE:
            return  # Слишком маленький пакет — игнорируем

        try:
            # Пытаемся определить тип пакета (байт 4)
            packet_type = data[4]

            if packet_type == PacketType.INIT_HELLO:
                self._handle_hello(data, addr)
            elif packet_type == PacketType.INIT_RESPONSE:
                self._handle_response(data, addr)
            elif packet_type == PacketType.DATA:
                self._handle_data(data, addr)
            elif packet_type == PacketType.KEEPALIVE:
                self._handle_keepalive(data, addr)
            elif packet_type == PacketType.KEY_ROTATE:
                self._handle_key_rotate(data, addr)
            elif packet_type == PacketType.DISCONNECT:
                self._handle_disconnect(data, addr)
            else:
                logger.debug(f"Unknown packet type {packet_type:#x} from {addr}")

        except Exception as e:
            logger.debug(f"Error processing packet from {addr}: {e}")

    def _handle_hello(self, data: bytes, addr: Tuple[str, int]):
        """Обрабатывает INIT_HELLO."""
        # Payload начинается после заголовка
        try:
            packet = ShadowPacket.deserialize(data)
            result = self._handshake.handle_init_hello(packet.payload, addr)
            if result:
                response_bytes, session = result
                # Назначаем IP клиенту
                tunnel_ip = self._ip_pool.allocate()
                if tunnel_ip:
                    self._session_mgr.assign_tunnel_ip(session.session_id, tunnel_ip)
                self._transport.sendto(response_bytes, addr)
        except PacketError:
            pass

    def _handle_response(self, data: bytes, addr: Tuple[str, int]):
        """Обрабатывает INIT_RESPONSE."""
        session = self._session_mgr.get_session_by_addr(addr)
        if not session:
            return
        try:
            packet = ShadowPacket.deserialize(data, expected_magic=session.magic)
            response = self._handshake.handle_init_response(packet, session)
            if response:
                self._transport.sendto(response, addr)
        except PacketError:
            pass

    def _handle_data(self, data: bytes, addr: Tuple[str, int]):
        """Обрабатывает пакет данных — дешифрует и пишет в TUN."""
        session = self._session_mgr.get_session_by_addr(addr)
        if not session or session.state != SessionState.ESTABLISHED:
            return

        plaintext = self._pkt_handler.process_data_packet(data, session)
        if plaintext:
            self._tun.write_packet(plaintext)

    def _handle_keepalive(self, data: bytes, addr: Tuple[str, int]):
        """Обрабатывает keepalive."""
        session = self._session_mgr.get_session_by_addr(addr)
        if not session:
            return
        response = self._pkt_handler.handle_keepalive(session)
        self._transport.sendto(response, addr)

    def _handle_key_rotate(self, data: bytes, addr: Tuple[str, int]):
        """Обрабатывает запрос ротации ключей."""
        session = self._session_mgr.get_session_by_addr(addr)
        if not session or session.state != SessionState.ESTABLISHED:
            return
        response = self._pkt_handler.handle_key_rotation(data, session)
        if response:
            self._transport.sendto(response, addr)

    def _handle_disconnect(self, data: bytes, addr: Tuple[str, int]):
        """Обрабатывает отключение клиента."""
        session = self._session_mgr.get_session_by_addr(addr)
        if session:
            if session.tunnel_ip:
                self._ip_pool.release(session.tunnel_ip)
            self._session_mgr.remove_session(session.session_id)
            logger.info(f"Client disconnected: {addr}")

    def send_to_client(self, session: SessionInfo, ip_packet: bytes):
        """Отправляет зашифрованный пакет клиенту."""
        if not session.remote_addr or not self._transport:
            return
        encrypted = self._pkt_handler.build_data_packet(ip_packet, session)
        if encrypted:
            self._transport.sendto(encrypted, session.remote_addr)

    def error_received(self, exc: Exception):
        logger.error(f"UDP error: {exc}")


class TunReader:
    """
    Читает пакеты из TUN-интерфейса и направляет клиентам.
    Работает в отдельном потоке/задаче asyncio.
    """

    def __init__(
        self,
        tun: TunInterface,
        session_manager: SessionManager,
        tunnel_protocol: ShadowTunnelProtocol,
    ):
        self._tun = tun
        self._session_mgr = session_manager
        self._protocol = tunnel_protocol
        self._running = False

    async def run(self):
        """Основной цикл чтения из TUN."""
        self._running = True
        loop = asyncio.get_event_loop()

        logger.info("TUN reader started")
        while self._running:
            try:
                # Читаем из TUN в executor (блокирующий вызов)
                ip_packet = await loop.run_in_executor(
                    None, self._tun.read_packet
                )
                if ip_packet:
                    self._route_packet(ip_packet)
            except Exception as e:
                logger.error(f"TUN read error: {e}")
                await asyncio.sleep(0.01)

    def _route_packet(self, ip_packet: bytes):
        """Маршрутизирует IP-пакет из TUN к нужному клиенту."""
        dst_ip = extract_dst_ip(ip_packet)
        if not dst_ip:
            return

        session = self._session_mgr.get_session_by_tunnel_ip(dst_ip)
        if session and session.state == SessionState.ESTABLISHED:
            self._protocol.send_to_client(session, ip_packet)

    def stop(self):
        self._running = False


async def maintenance_loop(session_manager: SessionManager, interval: int = 30):
    """Периодическая очистка истёкших сессий и служебные задачи."""
    while True:
        await asyncio.sleep(interval)
        session_manager.cleanup_expired()
