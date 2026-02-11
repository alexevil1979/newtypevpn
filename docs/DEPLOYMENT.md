# ShadowTunnel — Руководство по развёртыванию

## Требования

### Сервер
- Ubuntu 22.04+ (рекомендуется) или любой Linux с ядром 4.19+
- Python 3.10+
- 512 MB RAM (минимум), 1 GB рекомендуется
- UDP-порт 51820 открыт
- Root-доступ (для TUN и iptables)

### Windows-клиент
- Windows 10/11
- 100 MB свободного места

### Android-клиент
- Android 10+ (API 29)
- 50 MB свободного места

---

## Установка сервера

### Вариант 1: Автоматическая установка

```bash
git clone https://github.com/alexevil1979/newtypevpn.git
cd newtypevpn
sudo chmod +x scripts/install.sh
sudo ./scripts/install.sh
```

Скрипт выполнит:
1. Установку Python, pip, openssl, iptables, ufw
2. Создание `/opt/shadowtunnel` и `/etc/shadowtunnel`
3. Настройку Python virtual environment
4. Генерацию серверных ключей Ed25519
5. Генерацию SSL-сертификата для admin panel
6. Настройку UFW (открытие UDP 51820)
7. Включение IP forwarding
8. Установку systemd-сервиса

### Вариант 2: Docker

```bash
cd docker
# Создайте директорию для конфигурации
mkdir -p config
cp ../server/config.yaml config/

# Отредактируйте конфигурацию
nano config/config.yaml

# Запустите
docker-compose up -d

# Проверьте логи
docker-compose logs -f
```

**Важно**: Docker-контейнер требует `--cap-add=NET_ADMIN` и `--device=/dev/net/tun`.

### Вариант 3: Ручная установка

```bash
# 1. Зависимости
sudo apt install python3 python3-pip python3-venv iptables

# 2. Clone
git clone https://github.com/alexevil1979/newtypevpn.git /opt/shadowtunnel
cd /opt/shadowtunnel

# 3. Virtual environment
python3 -m venv venv
source venv/bin/activate
pip install -r server/requirements.txt
pip install -r admin/requirements.txt

# 4. Ключи
python scripts/generate_keys.py --output-dir /etc/shadowtunnel --type server

# 5. Конфигурация
sudo mkdir -p /etc/shadowtunnel
sudo cp server/config.yaml /etc/shadowtunnel/config.yaml
sudo nano /etc/shadowtunnel/config.yaml

# 6. Systemd
sudo cp server/shadowtunnel.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now shadowtunnel
```

---

## Конфигурация сервера

Файл: `/etc/shadowtunnel/config.yaml`

### Основные параметры

```yaml
server:
  listen_addr: "0.0.0.0"     # Все интерфейсы
  listen_port: 51820          # UDP-порт
  max_clients: 256            # Макс. клиентов
  log_level: "INFO"           # DEBUG для отладки

tunnel:
  subnet: "10.8.0.0/24"      # Подсеть туннеля
  server_ip: "10.8.0.1"      # IP сервера в туннеле
  mtu: 1400

nat:
  enabled: true
  interface: "eth0"           # Ваш внешний интерфейс!
```

### Определение внешнего интерфейса

```bash
ip route | grep default
# Пример: default via 10.0.0.1 dev eth0
# Интерфейс = eth0
```

---

## Добавление клиентов

### 1. Генерация ключей клиента

```bash
cd /opt/shadowtunnel
source venv/bin/activate
python scripts/generate_keys.py --type client --name myclient \
    --output-dir /tmp/client-keys \
    --server-addr YOUR_SERVER_IP \
    --server-port 51820 \
    --server-pub "$(cat /etc/shadowtunnel/server.pub | base64 -w0)"
```

### 2. Добавление в конфигурацию сервера

```yaml
auth:
  clients:
    - name: "myclient"
      public_key: "BASE64_PUBLIC_KEY_HERE"
```

### 3. Перезапуск сервера

```bash
sudo systemctl restart shadowtunnel
```

---

## Настройка клиентов

### Windows

1. Скачайте `ShadowTunnel.exe` из GitHub Releases
2. Скопируйте `myclient_config.yaml` на Windows
3. Запустите ShadowTunnel.exe
4. Import File → выберите конфигурацию
5. Нажмите Connect

### Android

1. Скачайте APK из GitHub Releases
2. Установите (разрешите неизвестные источники)
3. Импортируйте конфигурацию (файл)
4. Нажмите Connect

---

## Admin Panel

### Доступ

По умолчанию: `https://localhost:8443`
- Логин: `admin`
- Пароль: `shadowtunnel` (смените!)

### Смена пароля

```bash
source /opt/shadowtunnel/venv/bin/activate
python -c "
import bcrypt
password = input('New password: ')
h = bcrypt.hashpw(password.encode(), bcrypt.gensalt(12))
print(f'password_hash: \"{h.decode()}\"')
"
# Вставьте результат в config.yaml
```

### Удалённый доступ через SSH-туннель

```bash
ssh -L 8443:localhost:8443 user@your-server
# Откройте: https://localhost:8443
```

### Production: через Nginx

```bash
sudo cp nginx/shadowtunnel.conf /etc/nginx/sites-available/
sudo ln -s /etc/nginx/sites-available/shadowtunnel.conf /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl reload nginx
```

---

## VPS Git Synchronization

### Настройка

```bash
# На VPS:
ssh user@vps "git init --bare /opt/shadowtunnel.git"

# Локально:
./scripts/sync_with_vps.sh --setup user@vps:/opt/shadowtunnel.git
```

### Использование

```bash
# Двусторонняя синхронизация
./scripts/sync_with_vps.sh --sync

# Только push
./scripts/sync_with_vps.sh --push

# Только pull
./scripts/sync_with_vps.sh --pull

# Статус
./scripts/sync_with_vps.sh --status
```

### Автосинхронизация (cron)

```bash
# Каждые 5 минут
crontab -e
*/5 * * * * cd /opt/shadowtunnel && ./scripts/sync_with_vps.sh --sync >> /var/log/shadowtunnel/sync.log 2>&1
```

---

## GitHub Deployment

### Первичная настройка

```bash
cd /opt/shadowtunnel
git remote add origin https://github.com/alexevil1979/newtypevpn.git
```

### Деплой

```bash
./scripts/deploy_to_git.sh
```

### CI/CD

При push в `main`:
- Запускаются тесты
- Собирается Docker-образ
- При создании тега `v*` — создаётся Release с бинарниками

---

## Мониторинг

### Логи

```bash
# Systemd
journalctl -u shadowtunnel -f

# Файл логов
tail -f /var/log/shadowtunnel/server.log

# Docker
docker-compose logs -f
```

### Статус

```bash
systemctl status shadowtunnel
```

### API мониторинга

```bash
# Через SSH-туннель
curl -k https://localhost:8443/api/status \
  -H "Cookie: access_token=YOUR_JWT_TOKEN"
```

---

## Troubleshooting

### Сервер не запускается

```bash
# Проверьте логи
journalctl -u shadowtunnel -n 50

# Проверьте конфигурацию
python -c "import yaml; yaml.safe_load(open('/etc/shadowtunnel/config.yaml'))"

# Проверьте порт
ss -ulnp | grep 51820
```

### Клиент не подключается

1. Проверьте, открыт ли порт: `nc -zu server_ip 51820`
2. Проверьте firewall: `sudo ufw status`
3. Проверьте IP forwarding: `cat /proc/sys/net/ipv4/ip_forward`
4. Проверьте NAT: `sudo iptables -t nat -L -n`

### Нет интернета через туннель

```bash
# На сервере:
sudo iptables -t nat -A POSTROUTING -s 10.8.0.0/24 -o eth0 -j MASQUERADE
echo 1 > /proc/sys/net/ipv4/ip_forward
```
