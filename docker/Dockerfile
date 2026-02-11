# ═══════════════════════════════════════════════════════════
# ShadowTunnel Server — Docker Image
# ═══════════════════════════════════════════════════════════

FROM python:3.11-slim

LABEL maintainer="ShadowTunnel"
LABEL description="ShadowTunnel VPN Server"

# Системные зависимости
RUN apt-get update && apt-get install -y --no-install-recommends \
    iptables \
    iproute2 \
    openssl \
    && rm -rf /var/lib/apt/lists/*

# Рабочая директория
WORKDIR /opt/shadowtunnel

# Копируем requirements и устанавливаем зависимости
COPY server/requirements.txt /tmp/server-requirements.txt
COPY admin/requirements.txt /tmp/admin-requirements.txt
RUN pip install --no-cache-dir -r /tmp/server-requirements.txt \
    -r /tmp/admin-requirements.txt

# Копируем исходники
COPY shared/ ./shared/
COPY server/ ./server/
COPY admin/ ./admin/

# Создаём директории
RUN mkdir -p /etc/shadowtunnel /var/log/shadowtunnel

# Копируем дефолтную конфигурацию
COPY server/config.yaml /etc/shadowtunnel/config.yaml

# Генерируем ключи при сборке (перезаписываются при mount)
RUN python scripts/generate_keys.py --output-dir /etc/shadowtunnel --type server 2>/dev/null || true

# Копируем скрипт генерации ключей
COPY scripts/generate_keys.py ./scripts/

# Переменные окружения
ENV PYTHONPATH=/opt/shadowtunnel
ENV PYTHONUNBUFFERED=1
ENV SHADOWTUNNEL_CONFIG=/etc/shadowtunnel/config.yaml

# Порты: VPN (UDP) + Admin (TCP)
EXPOSE 51820/udp
EXPOSE 8443/tcp

# Для работы с TUN требуются привилегии
# Запуск: docker run --cap-add=NET_ADMIN --device=/dev/net/tun ...

# Healthcheck
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD python -c "import socket; s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.settimeout(2); s.close()" || exit 1

# Точка входа
CMD ["python", "-m", "server.main", "--config", "/etc/shadowtunnel/config.yaml"]
