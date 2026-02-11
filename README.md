# ShadowTunnel

**ShadowTunnel** — безопасная VPN-подобная система туннелирования с собственным обфусцированным протоколом, разработанная с нуля. Трафик маскируется под HTTPS или случайные данные, что обеспечивает устойчивость к блокировкам и DPI.

> ⚠️ Проект создан в образовательных целях. Используйте ответственно и в соответствии с законодательством вашей юрисдикции.

---

## Ключевые особенности

- 🔐 **Собственный протокол** на базе UDP с шифрованием AES-256-GCM, аутентификацией Ed25519, HMAC для целостности
- 🛡️ **Perfect Forward Secrecy** — ротация ключей каждые 30 минут
- 🎭 **Обфускация** — трафик маскируется под HTTPS или случайные данные
- 🖥️ **Сервер** — Python/asyncio на Ubuntu 22.04+
- 🪟 **Windows-клиент** — PyQt6 GUI с автопереподключением
- 📱 **Android-клиент** — Kotlin/Material Design, Android 10+ без root
- 🌐 **Веб-панель администратора** — FastAPI с JWT-аутентификацией
- 🔄 **CI/CD** — GitHub Actions для автоматической сборки и деплоя
- 🐳 **Docker** — контейнеризация серверной части

---

## Структура проекта

```
shadowtunnel/
├── README.md                   # Этот файл
├── LICENSE                     # MIT License
├── shared/                     # Общая библиотека протокола
│   ├── constants.py            # Константы протокола
│   ├── crypto.py               # Криптографические примитивы
│   ├── packet.py               # Формат пакетов
│   └── session.py              # Управление сессиями
├── server/                     # Серверная часть
│   ├── main.py                 # Точка входа сервера
│   ├── tunnel.py               # UDP-туннель
│   ├── nat.py                  # NAT и маршрутизация
│   ├── config.yaml             # Конфигурация
│   ├── requirements.txt        # Python-зависимости
│   └── shadowtunnel.service    # Systemd-юнит
├── admin/                      # Веб-панель администратора
│   ├── app.py                  # FastAPI-приложение
│   ├── auth.py                 # JWT-аутентификация
│   ├── templates/              # Jinja2-шаблоны
│   └── static/                 # CSS/JS
├── win-client/                 # Windows-клиент
│   ├── main.py                 # Точка входа
│   ├── gui.py                  # PyQt6 GUI
│   ├── tunnel.py               # Клиентский туннель
│   └── requirements.txt        # Зависимости
├── android-client/             # Android-клиент
│   ├── app/src/main/           # Kotlin-исходники
│   ├── build.gradle            # Gradle-конфигурация
│   └── settings.gradle
├── scripts/                    # Скрипты установки и деплоя
│   ├── install.sh              # Установка сервера
│   ├── deploy_to_git.sh        # Деплой в GitHub
│   ├── sync_with_vps.sh        # Синхронизация с VPS
│   └── generate_keys.py        # Генерация ключей
├── tests/                      # Тесты
│   ├── test_protocol.py        # Тесты протокола
│   ├── test_crypto.py          # Тесты криптографии
│   └── test_admin.py           # Тесты админ-панели
├── docker/                     # Docker-файлы
│   ├── Dockerfile
│   └── docker-compose.yml
├── nginx/                      # Конфигурация Nginx
│   └── shadowtunnel.conf
├── docs/                       # Документация
│   ├── PROTOCOL.md             # Спецификация протокола
│   ├── SECURITY.md             # Модель безопасности
│   └── DEPLOYMENT.md           # Руководство по развёртыванию
└── .github/workflows/
    └── deploy.yml              # CI/CD pipeline
```

---

## Быстрый старт

### Сервер (Ubuntu 22.04+)

```bash
# Клонировать репозиторий
git clone https://github.com/alexevil1979/newtypevpn.git
cd newtypevpn

# Запустить установку
chmod +x scripts/install.sh
sudo ./scripts/install.sh

# Отредактировать конфигурацию
nano server/config.yaml

# Запустить сервис
sudo systemctl start shadowtunnel
sudo systemctl enable shadowtunnel

# Проверить статус
sudo systemctl status shadowtunnel
```

### Windows-клиент

1. Скачайте `ShadowTunnel-Win.exe` из [GitHub Releases](https://github.com/alexevil1979/newtypevpn/releases)
2. Запустите и импортируйте конфигурацию (файл `.yaml` или QR-код)
3. Нажмите **Connect**

### Android-клиент

1. Скачайте `ShadowTunnel.apk` из [GitHub Releases](https://github.com/alexevil1979/newtypevpn/releases)
2. Установите APK (разрешите установку из неизвестных источников)
3. Отсканируйте QR-код конфигурации или импортируйте файл
4. Нажмите **Подключиться**

### Веб-панель администратора

```bash
# Панель доступна после установки сервера
# По умолчанию: https://localhost:8443
# Логин/пароль задаются в config.yaml

# Для удалённого доступа через SSH-туннель:
ssh -L 8443:localhost:8443 user@your-server
```

---

## Синхронизация с VPS

```bash
# На VPS — создать bare-репозиторий:
ssh user@vps "git init --bare /opt/shadowtunnel.git"

# Локально — настроить и запустить синхронизацию:
chmod +x scripts/sync_with_vps.sh
./scripts/sync_with_vps.sh --setup user@vps:/opt/shadowtunnel.git
./scripts/sync_with_vps.sh --sync
```

---

## Деплой в GitHub

```bash
chmod +x scripts/deploy_to_git.sh
./scripts/deploy_to_git.sh
```

---

## Docker

```bash
cd docker
docker-compose up -d
```

---

## Тестирование

```bash
pip install -r tests/requirements.txt
pytest tests/ -v --tb=short
```

---

## Безопасность

- **Шифрование**: AES-256-GCM с nonce
- **Аутентификация**: Ed25519 для подписей, HMAC-SHA256 для целостности
- **Forward Secrecy**: X25519 ECDH, ротация ключей каждые 30 минут
- **Anti-replay**: Временные метки + скользящее окно
- **Обфускация**: Padding, маскировка заголовков, имитация TLS ClientHello

Подробнее: [docs/SECURITY.md](docs/SECURITY.md)

---

## Лицензия

MIT License. См. [LICENSE](LICENSE).

---

## Вклад в проект

Pull requests приветствуются! Пожалуйста, прочитайте [docs/PROTOCOL.md](docs/PROTOCOL.md) перед внесением изменений в протокол.
