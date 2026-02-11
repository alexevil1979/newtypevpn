# AI_CONTEXT — ShadowTunnel Security Audit State

> Последнее обновление: 2026-02-11
> Фаза: **Полный аудит безопасности завершён. Ожидание исправлений.**

---

## Текущее состояние проекта

ShadowTunnel — кастомная VPN-система (UDP, AES-256-GCM + Ed25519 + HMAC, 3-way handshake, ротация ключей каждые 30 мин, обфускация, сервер Python/asyncio, Windows-клиент PyQt6, Android-клиент Kotlin, веб-админка FastAPI).

### Что сделано

- Полный security-аудит всех компонентов (протокол, крипто, handshake, обфускация, сервер, клиенты, веб-админка, деплой).
- Проаудированы все файлы: `shared/crypto.py`, `shared/packet.py`, `shared/session.py`, `shared/constants.py`, `server/tunnel.py`, `server/main.py`, `server/nat.py`, `server/protocol/handshake.py`, `server/protocol/handler.py`, `win-client/tunnel.py`, `win-client/gui.py`, `win-client/config.py`, `admin/app.py`, `admin/auth.py`, `android-client/.../ShadowTunnelVpnService.kt`, `android-client/.../ShadowCrypto.kt`, `android-client/.../ShadowPacket.kt`, `nginx/shadowtunnel.conf`, `scripts/install.sh`, `scripts/deploy_to_git.sh`, `scripts/sync_with_vps.sh`, `tests/test_crypto.py`, `tests/test_protocol.py`, `server/config.yaml`, `.github/workflows/deploy.yml`.

---

## Найденные уязвимости (сводка)

### CRITICAL (11 шт.)

| ID | Компонент | Описание |
|----|-----------|----------|
| CRIT-01 | `server/protocol/handshake.py` | Подпись клиента в INIT_HELLO **не верифицируется** → полный обход аутентификации |
| CRIT-02 | `server/protocol/handshake.py` | Подпись challenge-response в INIT_RESPONSE **не верифицируется** |
| CRIT-03 | `server/protocol/handshake.py` | Пустой `authorized_keys` → anonymous access для всех |
| CRIT-04 | `shared/crypto.py` | Ротация ключей использует `os.urandom(32)` как IKM — **разный на клиенте и сервере** → ключи расходятся, связь рвётся через 30 мин |
| CRIT-05 | `win-client/tunnel.py` | Клиент **не проверяет идентичность сервера** — нет верификации server_sig → тривиальный MITM |
| CRIT-06 | `shared/packet.py`, `shared/constants.py` | TLS-мимикрия поверх UDP — бессмысленна, DPI детектит мгновенно |
| CRIT-07 | `win-client/tunnel.py:335` | Windows-клиент **не туннелирует трафик** — TUN/TAP = `# TODO` |
| CRIT-08 | Все клиенты | **Нет Kill Switch** — при разрыве VPN трафик идёт в открытую |
| CRIT-09 | Все клиенты | **Нет защиты от DNS leak** |
| CRIT-10 | `admin/app.py` | Дефолтный пароль `admin/shadowtunnel`, логируется в открытом виде |
| CRIT-11 | `admin/app.py` | RCE-цепочка: `/api/config/update` + `/api/service/restart` |

### HIGH (18 шт.)

| ID | Компонент | Описание |
|----|-----------|----------|
| HIGH-01 | `shared/packet.py` | Весь заголовок (47 байт) в открытом виде — session_id, timestamp, sequence, packet_type, payload_length |
| HIGH-02 | `shared/crypto.py` | HKDF без transcript binding (нет session_id / eph keys в info) |
| HIGH-03 | `shared/packet.py` | Фиксированная структура заголовка = DPI-фингерпринт |
| HIGH-04 | `shared/constants.py` | Keepalive каждые 25 сек = паттерн для traffic analysis |
| HIGH-05 | `server/tunnel.py` | Нет rate limiting на INIT_HELLO → CPU exhaustion DoS |
| HIGH-06 | `server/tunnel.py` | IP-пакеты в TUN без валидации source IP → IP spoofing через туннель |
| HIGH-07 | `server/tunnel.py` | Thread safety: TunReader + asyncio event loop = race condition |
| HIGH-08 | Android клиент | **IPv6 leak** — нет `addRoute("::", 0)` |
| HIGH-09 | `win-client/tunnel.py` | Клиент не проверяет server public key (нет pinning) |
| HIGH-10 | Android клиент | Ключи хранятся без Android Keystore |
| HIGH-11 | `admin/app.py` | CSRF-защита объявлена, но **не используется** ни в одном endpoint |
| HIGH-12 | `admin/app.py` | CSP: `script-src 'unsafe-inline'` → XSS |
| HIGH-13 | `admin/app.py` | Нет rate limiting на `/login` |
| HIGH-14 | `scripts/deploy_to_git.sh` | GitHub repo URL и username захардкожены |
| HIGH-15 | `scripts/install.sh` | SSH-ключ без passphrase (`-N ""`) |
| HIGH-16 | `shared/session.py` | Replay window bitmap растёт неограниченно (memory leak) |
| HIGH-17 | `shared/crypto.py` | Приватный ключ на диске без шифрования (`NoEncryption()`) |
| HIGH-18 | `server/tunnel.py` | DISCONNECT без проверки HMAC → spoofed disconnect убивает сессию |

### MEDIUM (12 шт.)

| ID | Описание |
|----|----------|
| MED-01 | Дублирование правил iptables при перезапуске |
| MED-02 | Версия сервера в логах (`ShadowTunnel Server v1.0.0`) |
| MED-03 | Reconnect без проверки закрытия старого сокета → IP leak |
| MED-04 | Кастомная JWT-реализация вместо PyJWT |
| MED-05 | JWT без механизма отзыва (нет blacklist) |
| MED-06 | CORSMiddleware импортирован но не настроен |
| MED-07 | Bare git repo на VPS — полная кодовая база через SSH |
| MED-08 | Дефолтный пароль в install.sh в открытом виде |
| MED-09 | cleanup_expired() не чистит ESTABLISHED-зомби |
| MED-10 | TIMESTAMP_TOLERANCE = 30 сек — большое окно для replay |
| MED-11 | Sequence number overflow → replay после 2^32 пакетов |
| MED-12 | `clear_keys()` не wipe memory (Python GC) |

### LOW (5 шт.)

| ID | Описание |
|----|----------|
| LOW-01 | Порт 51820 совпадает с WireGuard |
| LOW-02 | FastAPI metadata может выдать framework |
| LOW-03 | Git repo root = C:\Users\1 (домашняя директория) |
| LOW-04 | payload_length uint16 без валидации MAX_PAYLOAD_SIZE |
| LOW-05 | Android: MTU 1400 захардкожен |

---

## Следующие шаги (приоритет)

### Шаг 1 — CRITICAL fixes (блокирующие, делать ПЕРВЫМИ)

1. **`server/protocol/handshake.py`** — Добавить верификацию Ed25519-подписи клиента в `handle_init_hello()` и `handle_init_response()` (CRIT-01, CRIT-02)
2. **`server/protocol/handshake.py`** — Убрать anonymous access при пустом `authorized_keys`, возвращать `None` (CRIT-03)
3. **`shared/crypto.py`** — Исправить `derive_rotation_keys()`: использовать `current_key` как IKM вместо `os.urandom(32)` для детерминистической деривации (CRIT-04)
4. **`win-client/tunnel.py`** — Добавить верификацию server_sig при получении INIT_CHALLENGE (CRIT-05)
5. **`win-client/tunnel.py`** — Реализовать TUN/wintun интеграцию или чётко пометить клиент как нерабочий (CRIT-07)
6. **`admin/app.py`** — Запретить запуск без установленного пароля, убрать дефолтный пароль (CRIT-10)
7. **`admin/app.py`** — Валидировать config update: whitelist допустимых ключей, убрать `systemctl restart` (CRIT-11)

### Шаг 2 — HIGH fixes

8. Зашифровать заголовок или хотя бы session_id/timestamp/sequence (HIGH-01)
9. Добавить transcript binding в HKDF info (HIGH-02)
10. Rate limiting на INIT_HELLO по source IP (HIGH-05)
11. Валидация source IP при записи в TUN (HIGH-06)
12. Проверка HMAC для DISCONNECT-пакетов (HIGH-18)
13. Ограничить bitmap в ReplayWindow (HIGH-16)
14. Kill switch для клиентов (CRIT-08)
15. DNS leak prevention (CRIT-09)
16. IPv6 route на Android (HIGH-08)
17. Активировать CSRF-защиту в admin (HIGH-11)
18. Исправить CSP — убрать `unsafe-inline` (HIGH-12)

### Шаг 3 — Security tests

19. Написать тесты, которые ОБЯЗАНЫ проваливаться при отсутствии фиксов (см. раздел "Обязательные тесты безопасности" в аудите)
20. Fuzzing harness для packet deserialize и datagram_received
21. Integration test: ротация ключей даёт одинаковый результат на клиенте и сервере

### Шаг 4 — Обфускация (полная переработка)

22. Переработать обфускацию: убрать бессмысленную TLS-мимикрию через UDP
23. Зашифровать весь пакет (включая заголовок) или использовать проверенные подходы (obfs4, shadowsocks-like)
24. Рандомизировать размеры пакетов и тайминги

---

## Архитектура (компоненты)

```
nevpn/
├── shared/          # Общая библиотека (crypto, packet, session, constants)
├── server/          # Сервер (asyncio UDP, TUN, NAT, handshake, handler)
├── win-client/      # Windows-клиент (PyQt6, TUN — НЕ РЕАЛИЗОВАН)
├── android-client/  # Android-клиент (Kotlin, VpnService)
├── admin/           # Веб-админка (FastAPI, JWT, Jinja2)
├── tests/           # Тесты (pytest, hypothesis)
├── scripts/         # Скрипты деплоя (install.sh, deploy_to_git.sh)
├── docker/          # Docker (Dockerfile, docker-compose.yml)
├── nginx/           # Nginx reverse proxy конфиг
├── docs/            # Документация (PROTOCOL.md, SECURITY.md, DEPLOYMENT.md)
└── .github/         # CI/CD (GitHub Actions)
```

## Ключевые файлы для исправлений

| Файл | Что исправлять |
|------|---------------|
| `shared/crypto.py` | derive_rotation_keys, clear_keys, HKDF info, NoEncryption |
| `shared/packet.py` | Шифрование заголовка, обфускация |
| `shared/session.py` | ReplayWindow bitmap bound, cleanup logic |
| `server/protocol/handshake.py` | Верификация подписей, anonymous access |
| `server/tunnel.py` | Rate limiting, HMAC на disconnect, IP validation, thread safety |
| `server/protocol/handler.py` | Source IP validation при записи в TUN |
| `win-client/tunnel.py` | Server verification, TUN implementation, kill switch |
| `admin/app.py` | Default password, CSRF, CSP, config update validation |
| `android-client/.../ShadowTunnelVpnService.kt` | IPv6 route, DNS leak, kill switch |
