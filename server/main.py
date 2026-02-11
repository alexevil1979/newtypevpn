#!/usr/bin/env python3
"""
ShadowTunnel Server — точка входа.

Запуск:
    python -m server.main --config server/config.yaml

Или через systemd:
    systemctl start shadowtunnel
"""

import asyncio
import argparse
import logging
import signal
import sys
import os
import pathlib

import yaml

# Добавляем корень проекта в PATH
PROJECT_ROOT = str(pathlib.Path(__file__).resolve().parents[1])
sys.path.insert(0, PROJECT_ROOT)

from shared.crypto import ShadowCrypto
from shared.session import SessionManager
from server.protocol.handshake import ServerHandshake
from server.protocol.handler import PacketHandler
from server.tunnel import (
    ShadowTunnelProtocol,
    TunReader,
    maintenance_loop,
)
from server.nat import TunInterface, NATManager, IPPool

logger = logging.getLogger("shadowtunnel")


def load_config(config_path: str) -> dict:
    """Загружает конфигурацию из YAML-файла."""
    with open(config_path, "r", encoding="utf-8") as f:
        config = yaml.safe_load(f)
    return config


def setup_logging(config: dict):
    """Настраивает логирование."""
    level = getattr(logging, config.get("server", {}).get("log_level", "INFO"))
    log_file = config.get("server", {}).get("log_file", "")

    handlers = [logging.StreamHandler(sys.stdout)]
    if log_file:
        os.makedirs(os.path.dirname(log_file), exist_ok=True)
        handlers.append(logging.FileHandler(log_file))

    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        handlers=handlers,
    )


def load_server_keys(config: dict):
    """Загружает или генерирует ключи сервера."""
    crypto_cfg = config.get("crypto", {})
    priv_path = crypto_cfg.get("private_key_file", "/etc/shadowtunnel/server.key")
    pub_path = crypto_cfg.get("public_key_file", "/etc/shadowtunnel/server.pub")

    if os.path.exists(priv_path):
        with open(priv_path, "rb") as f:
            private_key = ShadowCrypto.deserialize_private_key(f.read())
        logger.info(f"Server private key loaded from {priv_path}")
    else:
        logger.warning("Server key not found, generating new keypair...")
        private_key, public_key = ShadowCrypto.generate_identity_keypair()

        os.makedirs(os.path.dirname(priv_path), exist_ok=True)
        with open(priv_path, "wb") as f:
            f.write(ShadowCrypto.serialize_private_key(private_key))
        os.chmod(priv_path, 0o600)

        with open(pub_path, "wb") as f:
            f.write(ShadowCrypto.serialize_public_key(public_key))

        logger.info(f"New keypair generated: {priv_path}, {pub_path}")

    return private_key


def load_authorized_keys(config: dict) -> dict:
    """Загружает публичные ключи авторизованных клиентов."""
    import base64
    auth_cfg = config.get("auth", {})
    clients = auth_cfg.get("clients", [])
    authorized = {}

    for client in clients:
        name = client.get("name", "")
        pub_key_b64 = client.get("public_key", "")
        if name and pub_key_b64:
            try:
                authorized[name] = base64.b64decode(pub_key_b64)
            except Exception as e:
                logger.warning(f"Failed to load key for {name}: {e}")

    logger.info(f"Loaded {len(authorized)} authorized client keys")
    return authorized


async def run_server(config: dict):
    """Основная функция запуска сервера."""
    server_cfg = config.get("server", {})
    tunnel_cfg = config.get("tunnel", {})
    nat_cfg = config.get("nat", {})

    listen_addr = server_cfg.get("listen_addr", "0.0.0.0")
    listen_port = server_cfg.get("listen_port", 51820)
    max_clients = server_cfg.get("max_clients", 256)

    subnet = tunnel_cfg.get("subnet", "10.8.0.0/24")
    server_ip = tunnel_cfg.get("server_ip", "10.8.0.1")
    mtu = tunnel_cfg.get("mtu", 1400)

    # Инициализация компонентов
    session_manager = SessionManager(max_sessions=max_clients)
    ip_pool = IPPool(subnet, server_ip)

    # Загружаем ключи
    server_key = load_server_keys(config)
    authorized_keys = load_authorized_keys(config)

    # Создаём обработчики
    handshake = ServerHandshake(server_key, session_manager, authorized_keys)
    packet_handler = PacketHandler()

    # Создаём TUN-интерфейс
    tun = TunInterface(name="stun0", mtu=mtu)
    if os.geteuid() == 0:  # Только с root
        if not tun.create(server_ip, subnet):
            logger.error("Failed to create TUN interface")
            return
    else:
        logger.warning(
            "Not running as root — TUN interface not created. "
            "Packet forwarding will not work."
        )

    # Настраиваем NAT
    if nat_cfg.get("enabled", True) and os.geteuid() == 0:
        ext_iface = nat_cfg.get("interface", "eth0")
        nat_manager = NATManager(ext_iface, subnet)
        nat_manager.setup()
    else:
        nat_manager = None

    # Запускаем UDP-сервер
    loop = asyncio.get_event_loop()

    transport, protocol = await loop.create_datagram_endpoint(
        lambda: ShadowTunnelProtocol(
            session_manager,
            handshake,
            packet_handler,
            ip_pool,
            tun,
        ),
        local_addr=(listen_addr, listen_port),
    )

    logger.info(f"ShadowTunnel server listening on {listen_addr}:{listen_port}")
    logger.info(f"Tunnel subnet: {subnet}, Server IP: {server_ip}")

    # Запускаем TUN reader
    tun_reader = TunReader(tun, session_manager, protocol)
    tun_task = asyncio.create_task(tun_reader.run())

    # Запускаем maintenance loop
    maint_task = asyncio.create_task(maintenance_loop(session_manager))

    # Ожидаем сигнал остановки
    stop_event = asyncio.Event()

    def handle_signal():
        logger.info("Shutdown signal received")
        stop_event.set()

    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, handle_signal)
        except NotImplementedError:
            pass  # Windows

    await stop_event.wait()

    # Cleanup
    logger.info("Shutting down...")
    tun_reader.stop()
    tun_task.cancel()
    maint_task.cancel()
    transport.close()
    tun.close()
    if nat_manager:
        nat_manager.cleanup()

    logger.info("Server stopped")


def main():
    parser = argparse.ArgumentParser(description="ShadowTunnel VPN Server")
    parser.add_argument(
        "--config", "-c",
        default="server/config.yaml",
        help="Path to config file (default: server/config.yaml)",
    )
    args = parser.parse_args()

    config = load_config(args.config)
    setup_logging(config)

    logger.info("=" * 60)
    logger.info("  ShadowTunnel Server v1.0.0")
    logger.info("=" * 60)

    try:
        asyncio.run(run_server(config))
    except KeyboardInterrupt:
        logger.info("Interrupted")
    except Exception as e:
        logger.critical(f"Fatal error: {e}", exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    main()
