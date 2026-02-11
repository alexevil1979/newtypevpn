"""
ShadowTunnel Server — NAT и маршрутизация.

Управляет:
- Назначением IP-адресов клиентам
- NAT masquerade (iptables)
- IP forwarding
- TUN-интерфейсом
"""

import os
import struct
import socket
import logging
import subprocess
import ipaddress
from typing import Optional, Set

logger = logging.getLogger("shadowtunnel.nat")


class IPPool:
    """Пул IP-адресов для клиентов."""

    def __init__(self, subnet: str, server_ip: str):
        self._network = ipaddress.IPv4Network(subnet, strict=False)
        self._server_ip = ipaddress.IPv4Address(server_ip)
        self._allocated: Set[str] = set()
        self._allocated.add(str(self._server_ip))
        # Исключаем сетевой адрес и broadcast
        self._allocated.add(str(self._network.network_address))
        self._allocated.add(str(self._network.broadcast_address))

    def allocate(self) -> Optional[str]:
        """Выделяет следующий свободный IP из пула."""
        for host in self._network.hosts():
            ip_str = str(host)
            if ip_str not in self._allocated:
                self._allocated.add(ip_str)
                logger.info(f"IP allocated: {ip_str}")
                return ip_str
        logger.error("IP pool exhausted!")
        return None

    def release(self, ip: str):
        """Возвращает IP в пул."""
        self._allocated.discard(ip)
        logger.info(f"IP released: {ip}")

    @property
    def available_count(self) -> int:
        total = sum(1 for _ in self._network.hosts())
        return total - len(self._allocated)


class TunInterface:
    """
    Управление TUN-интерфейсом на Linux.
    Создаёт виртуальный сетевой интерфейс для туннелирования.
    """

    TUNSETIFF = 0x400454CA
    IFF_TUN = 0x0001
    IFF_NO_PI = 0x1000

    def __init__(self, name: str = "stun0", mtu: int = 1400):
        self.name = name
        self.mtu = mtu
        self._fd: Optional[int] = None

    def create(self, ip: str, subnet: str) -> bool:
        """Создаёт TUN-интерфейс и настраивает IP."""
        try:
            # Открываем /dev/net/tun
            self._fd = os.open("/dev/net/tun", os.O_RDWR)

            # Конфигурируем интерфейс
            import fcntl
            ifr = struct.pack("16sH", self.name.encode(), self.IFF_TUN | self.IFF_NO_PI)
            fcntl.ioctl(self._fd, self.TUNSETIFF, ifr)

            # Настраиваем IP и маршруты
            network = ipaddress.IPv4Network(subnet, strict=False)
            prefix_len = network.prefixlen

            subprocess.run(
                ["ip", "addr", "add", f"{ip}/{prefix_len}", "dev", self.name],
                check=True,
            )
            subprocess.run(
                ["ip", "link", "set", "dev", self.name, "mtu", str(self.mtu)],
                check=True,
            )
            subprocess.run(
                ["ip", "link", "set", "dev", self.name, "up"],
                check=True,
            )

            logger.info(f"TUN interface {self.name} created: {ip}/{prefix_len}")
            return True

        except (OSError, subprocess.CalledProcessError) as e:
            logger.error(f"Failed to create TUN interface: {e}")
            return False

    def read_packet(self) -> Optional[bytes]:
        """Читает пакет из TUN-интерфейса."""
        if self._fd is None:
            return None
        try:
            return os.read(self._fd, 65535)
        except OSError:
            return None

    def write_packet(self, data: bytes) -> bool:
        """Записывает пакет в TUN-интерфейс."""
        if self._fd is None:
            return False
        try:
            os.write(self._fd, data)
            return True
        except OSError:
            return False

    def close(self):
        """Закрывает TUN-интерфейс."""
        if self._fd is not None:
            os.close(self._fd)
            self._fd = None
            try:
                subprocess.run(
                    ["ip", "link", "delete", self.name],
                    check=False,
                )
            except Exception:
                pass
            logger.info(f"TUN interface {self.name} closed")


class NATManager:
    """
    Управление NAT и iptables.
    """

    def __init__(self, external_interface: str, tunnel_subnet: str):
        self._ext_iface = external_interface
        self._subnet = tunnel_subnet

    def setup(self) -> bool:
        """Настраивает NAT и IP forwarding."""
        try:
            # Включаем IP forwarding
            subprocess.run(
                ["sysctl", "-w", "net.ipv4.ip_forward=1"],
                check=True,
            )

            # NAT masquerade
            subprocess.run(
                [
                    "iptables", "-t", "nat", "-A", "POSTROUTING",
                    "-s", self._subnet,
                    "-o", self._ext_iface,
                    "-j", "MASQUERADE",
                ],
                check=True,
            )

            # Разрешаем forwarding
            subprocess.run(
                [
                    "iptables", "-A", "FORWARD",
                    "-i", "stun0",
                    "-o", self._ext_iface,
                    "-j", "ACCEPT",
                ],
                check=True,
            )
            subprocess.run(
                [
                    "iptables", "-A", "FORWARD",
                    "-i", self._ext_iface,
                    "-o", "stun0",
                    "-m", "state", "--state", "RELATED,ESTABLISHED",
                    "-j", "ACCEPT",
                ],
                check=True,
            )

            logger.info(f"NAT configured: {self._subnet} → {self._ext_iface}")
            return True

        except subprocess.CalledProcessError as e:
            logger.error(f"NAT setup failed: {e}")
            return False

    def cleanup(self):
        """Очищает правила iptables."""
        try:
            subprocess.run(
                [
                    "iptables", "-t", "nat", "-D", "POSTROUTING",
                    "-s", self._subnet,
                    "-o", self._ext_iface,
                    "-j", "MASQUERADE",
                ],
                check=False,
            )
            subprocess.run(
                ["iptables", "-D", "FORWARD", "-i", "stun0", "-o", self._ext_iface, "-j", "ACCEPT"],
                check=False,
            )
            logger.info("NAT rules cleaned up")
        except Exception as e:
            logger.warning(f"NAT cleanup warning: {e}")


def extract_dst_ip(ip_packet: bytes) -> Optional[str]:
    """Извлекает IP-адрес назначения из IP-пакета."""
    if len(ip_packet) < 20:
        return None
    version = (ip_packet[0] >> 4) & 0xF
    if version != 4:
        return None
    dst_ip = socket.inet_ntoa(ip_packet[16:20])
    return dst_ip


def extract_src_ip(ip_packet: bytes) -> Optional[str]:
    """Извлекает IP-адрес источника из IP-пакета."""
    if len(ip_packet) < 20:
        return None
    version = (ip_packet[0] >> 4) & 0xF
    if version != 4:
        return None
    src_ip = socket.inet_ntoa(ip_packet[12:16])
    return src_ip
