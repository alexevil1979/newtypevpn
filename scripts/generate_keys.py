#!/usr/bin/env python3
"""
ShadowTunnel — генерация криптографических ключей.

Использование:
    python scripts/generate_keys.py --output-dir /etc/shadowtunnel --type server
    python scripts/generate_keys.py --output-dir ./keys --type client --name myclient
"""

import os
import sys
import argparse
import base64

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from shared.crypto import ShadowCrypto


def generate_server_keys(output_dir: str):
    """Генерирует серверные ключи Ed25519."""
    os.makedirs(output_dir, exist_ok=True)

    private_key, public_key = ShadowCrypto.generate_identity_keypair()

    priv_path = os.path.join(output_dir, "server.key")
    pub_path = os.path.join(output_dir, "server.pub")

    with open(priv_path, "wb") as f:
        f.write(ShadowCrypto.serialize_private_key(private_key))

    with open(pub_path, "wb") as f:
        f.write(ShadowCrypto.serialize_public_key(public_key))

    # Также сохраняем base64-версию публичного ключа
    pub_raw = public_key.public_bytes_raw()
    pub_b64 = base64.b64encode(pub_raw).decode()

    print(f"Server keys generated:")
    print(f"  Private key: {priv_path}")
    print(f"  Public key:  {pub_path}")
    print(f"  Public key (base64): {pub_b64}")


def generate_client_keys(output_dir: str, name: str):
    """Генерирует клиентские ключи Ed25519."""
    os.makedirs(output_dir, exist_ok=True)

    private_key, public_key = ShadowCrypto.generate_identity_keypair()

    priv_path = os.path.join(output_dir, f"{name}.key")
    pub_path = os.path.join(output_dir, f"{name}.pub")

    with open(priv_path, "wb") as f:
        f.write(ShadowCrypto.serialize_private_key(private_key))

    with open(pub_path, "wb") as f:
        f.write(ShadowCrypto.serialize_public_key(public_key))

    pub_raw = public_key.public_bytes_raw()
    pub_b64 = base64.b64encode(pub_raw).decode()

    print(f"Client '{name}' keys generated:")
    print(f"  Private key: {priv_path}")
    print(f"  Public key:  {pub_path}")
    print(f"  Public key (base64): {pub_b64}")
    print()
    print(f"Add this to server config.yaml under auth.clients:")
    print(f'  - name: "{name}"')
    print(f'    public_key: "{pub_b64}"')


def generate_client_config(
    output_dir: str,
    name: str,
    server_addr: str,
    server_port: int,
    server_pub_b64: str,
):
    """Генерирует файл конфигурации клиента."""
    import yaml

    config = {
        "server": {
            "address": server_addr,
            "port": server_port,
            "dns": ["1.1.1.1", "8.8.8.8"],
        },
        "client": {
            "name": name,
            "obfuscation": "random_padding",
            "auto_reconnect": True,
            "keepalive_interval": 25,
            "log_level": "INFO",
        },
        "crypto": {
            "server_public_key": server_pub_b64,
            "private_key_file": f"{name}.key",
        },
    }

    config_path = os.path.join(output_dir, f"{name}_config.yaml")
    with open(config_path, "w") as f:
        yaml.dump(config, f, default_flow_style=False)

    print(f"Client config: {config_path}")


def main():
    parser = argparse.ArgumentParser(description="ShadowTunnel Key Generator")
    parser.add_argument(
        "--type", choices=["server", "client"], required=True,
        help="Type of keys to generate",
    )
    parser.add_argument(
        "--output-dir", "-o", default="./keys",
        help="Output directory for keys",
    )
    parser.add_argument(
        "--name", "-n", default="client1",
        help="Client name (for client type)",
    )
    parser.add_argument(
        "--server-addr", default="",
        help="Server address for client config generation",
    )
    parser.add_argument(
        "--server-port", type=int, default=51820,
        help="Server port for client config",
    )
    parser.add_argument(
        "--server-pub", default="",
        help="Server public key (base64) for client config",
    )

    args = parser.parse_args()

    if args.type == "server":
        generate_server_keys(args.output_dir)
    elif args.type == "client":
        generate_client_keys(args.output_dir, args.name)
        if args.server_addr:
            generate_client_config(
                args.output_dir,
                args.name,
                args.server_addr,
                args.server_port,
                args.server_pub,
            )


if __name__ == "__main__":
    main()
