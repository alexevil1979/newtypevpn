"""
ShadowTunnel Windows Client — конфигурация.
"""

import os
import yaml
import json
import base64
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class ClientConfig:
    """Конфигурация клиента."""
    server_addr: str = ""
    server_port: int = 51820
    server_public_key: str = ""
    client_name: str = ""
    private_key_file: str = ""
    obfuscation: str = "random_padding"
    dns: list = field(default_factory=lambda: ["1.1.1.1", "8.8.8.8"])
    auto_reconnect: bool = True
    keepalive_interval: int = 25
    log_level: str = "INFO"

    @classmethod
    def from_yaml(cls, path: str) -> "ClientConfig":
        """Загружает конфигурацию из YAML-файла."""
        with open(path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)

        server = data.get("server", {})
        client = data.get("client", {})
        crypto = data.get("crypto", {})

        return cls(
            server_addr=server.get("address", ""),
            server_port=server.get("port", 51820),
            server_public_key=crypto.get("server_public_key", ""),
            client_name=client.get("name", ""),
            private_key_file=crypto.get("private_key_file", ""),
            obfuscation=client.get("obfuscation", "random_padding"),
            dns=server.get("dns", ["1.1.1.1", "8.8.8.8"]),
            auto_reconnect=client.get("auto_reconnect", True),
            keepalive_interval=client.get("keepalive_interval", 25),
            log_level=client.get("log_level", "INFO"),
        )

    @classmethod
    def from_qr_data(cls, data: str) -> "ClientConfig":
        """Парсит конфигурацию из QR-кода (JSON base64)."""
        decoded = base64.b64decode(data).decode("utf-8")
        config_dict = json.loads(decoded)
        return cls(**config_dict)

    def to_yaml(self, path: str):
        """Сохраняет конфигурацию в YAML."""
        data = {
            "server": {
                "address": self.server_addr,
                "port": self.server_port,
                "dns": self.dns,
            },
            "client": {
                "name": self.client_name,
                "obfuscation": self.obfuscation,
                "auto_reconnect": self.auto_reconnect,
                "keepalive_interval": self.keepalive_interval,
                "log_level": self.log_level,
            },
            "crypto": {
                "server_public_key": self.server_public_key,
                "private_key_file": self.private_key_file,
            },
        }
        with open(path, "w", encoding="utf-8") as f:
            yaml.dump(data, f, default_flow_style=False)

    def is_valid(self) -> bool:
        """Проверяет минимальную валидность конфигурации."""
        return bool(self.server_addr and self.server_port)


def get_config_dir() -> str:
    """Возвращает путь к директории конфигурации клиента."""
    appdata = os.environ.get("APPDATA", os.path.expanduser("~"))
    config_dir = os.path.join(appdata, "ShadowTunnel")
    os.makedirs(config_dir, exist_ok=True)
    return config_dir
