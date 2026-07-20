# 3x-ui-setup

**Скилл Claude Code для автоматического развёртывания VPN-сервера**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE) ![Platform](https://img.shields.io/badge/Platform-Linux%20VPS-orange) ![Claude Code](https://img.shields.io/badge/Claude%20Code-Skill-blueviolet)

> **English version**: [README.md](README.md)

## Быстрая установка

```bash
curl -fsSL https://raw.githubusercontent.com/AndyShaman/3x-ui-skill/main/install.sh | bash
```

Или вручную:

```bash
git clone https://github.com/AndyShaman/3x-ui-skill.git
cp -r 3x-ui-skill/skill ~/.claude/skills/3x-ui-setup
rm -rf 3x-ui-skill
```

## Обзор

Скилл для Claude Code, который полностью автоматизирует развёртывание VPN-сервера на базе 3x-ui. Вы даёте свежий VPS (IP-адрес и root-пароль от провайдера) — скилл делает всё остальное: защищает сервер, устанавливает панель, создаёт два инбаунда VLESS+Reality (XHTTP + TCP/Vision), отдаёт их одной ссылкой-подпиской и помогает подключиться через клиент Happ.

Создан специально для новичков и заточен под реалии DPI в РФ на 2026 год. Не нужно разбираться в Linux, SSH или сетевых протоколах — достаточно запустить Claude Code и сказать, что вам нужен VPN.

## Возможности

- 🔒 **Полная защита сервера** — SSH-ключи, файрвол UFW, fail2ban (backend systemd), hardening ядра
- 📦 **Установка панели 3x-ui** — случайные учётные данные, панель только на loopback (доступ через SSH-туннель)
- ⚡ **Два инбаунда VLESS+Reality** — XHTTP (лучшая устойчивость к DPI) + TCP/Vision+padding (iOS и запасной)
- 🔗 **Одна ссылка-подписка** — оба профиля, автообновление, по HTTPS
- 🌐 **VLESS TLS** — опционально, с доменом и автоматическим SSL-сертификатом
- 🎭 **Фоллбэк-страница Nginx** — нейтральная маскировочная страница для режима TLS
- 📱 **Инструкции по подключению через Happ** — пошаговое руководство для клиента
- 🇷🇺 **Заточено под DPI РФ 2026** — fingerprint firefox, padding Vision, честная документация про белые списки
- 🖥️ **Удалённый и локальный режим** — работает через SSH с вашего компьютера или прямо на сервере
- ✅ **Пошаговое выполнение** — доступ по ключу проверяется до блокировки SSH
- 👻 **ICMP отключён** — сервер не отвечает на ping для повышения скрытности

## Процесс работы

```
Свежий VPS (IP + root + пароль)
  │
  ├─ Часть 1: Защита сервера
  │   ├─ Генерация SSH-ключа
  │   ├─ Обновление системы
  │   ├─ Создание пользователя + sudo
  │   ├─ Установка ключа (пользователю И root) + ТЕСТ входа по ключу
  │   ├─ Файрвол UFW
  │   ├─ Hardening ядра
  │   └─ SSH-конфиг (быстрый доступ)
  │
  ├─ Часть 2: Установка VPN
  │   ├─ Установка панели 3x-ui (только loopback) + BBR
  │   ├─ Отключение ICMP
  │   ├─ Два инбаунда VLESS+Reality (XHTTP 443 + TCP/Vision 8443)
  │   ├─ Subscription-сервер + LE-серт на IP
  │   └─ Настройка клиента Happ + проверка
  │
  ├─ Финализация (В КОНЦЕ, после проверки ключа)
  │   ├─ fail2ban (systemd)
  │   └─ Блокировка SSH (без root, без паролей)
  │
  └─ ✅ Защищённый сервер + Работающий VPN
```

## Что входит

| Файл | Описание |
|------|----------|
| `skill/SKILL.md` | Основной скилл — оркестрирующая «шина» |
| `skill/references/reality-inbound.md` | Сканер SNI + оба инбаунда VLESS+Reality (XHTTP + TCP/Vision) |
| `skill/references/subscription.md` | Subscription-сервер + LE-серт на голый IP + туннель к панели |
| `skill/references/client-happ.md` | Установка Happ, импорт, подключение, диагностика |
| `skill/references/finalize-hardening.md` | fail2ban + блокировка SSH с проверкой ключа |
| `skill/references/guide-template.md` | Шаблон методички + политика секретов |
| `skill/references/whitelist-and-fallbacks.md` | Ожидания по DPI РФ, лестница обхода, пул SNI |
| `skill/references/local-mode.md` | Отличия, когда Claude Code запущен на самом VPS |
| `skill/references/vless-tls.md` | Опциональный путь VLESS TLS (нужен домен) |
| `skill/references/fallback-nginx.md` | Опциональная нейтральная страница-заглушка для TLS |
| `install.sh` | Скрипт установки одной командой |

## Поддерживаемые протоколы

| Параметр | VLESS Reality | VLESS TLS |
|----------|---------------|-----------|
| Домен | Не нужен | Нужен |
| SSL-сертификат | Не нужен | Автоматический (acme.sh) |
| Сложность | Простой | Средний |
| Фоллбэк-страница | Встроенная (целевой сайт) | Опционально (Nginx) |
| Рекомендуется для | Новичков | Опытных |

## Использование

Установите скилл любым из способов выше, откройте Claude Code и скажите:

- *«Настрой VPN на моём VPS»*
- *«У меня новый сервер, помоги настроить VLESS»*
- *«Подними 3x-ui на моём сервере»*

Скилл активируется автоматически, когда Claude Code определит, что задача связана с настройкой VPN или 3x-ui.

## Требования

- **Claude Code** (CLI)
- **Свежий VPS** (Ubuntu/Debian) с root-доступом
- **SSH-доступ** с вашего компьютера
- **(Опционально)** Доменное имя — для режима VLESS TLS

## Решение проблем

| Проблема | Решение |
|----------|---------|
| Permission denied | Проверьте права SSH-ключа: `chmod 700 ~/.ssh && chmod 600 ~/.ssh/*` |
| Host key verification failed | Удалите старый ключ: `ssh-keygen -R <IP>` |
| Панель недоступна | SSH-туннель: `ssh -L <panel_port>:127.0.0.1:<panel_port> <nickname>` (порт панели случайный) |
| Reality не подключается | Перезапустите сканер SNI и выберите другой домен |
| iOS подключается, но нет интернета | Используйте профиль TCP/8443, не XHTTP (XHTTP+Reality сломан в Happ на iOS) |
| Работает по Wi-Fi, но не на мобильном | Регион с белыми списками — зарубежный VPS не поможет; см. `whitelist-and-fallbacks.md` |
| Забыли пароль от панели | Сбросьте: `sudo x-ui setting -reset` |

## Как помочь проекту

1. Сделайте форк репозитория
2. Создайте ветку для изменений (`git checkout -b feature/my-feature`)
3. Внесите изменения и зафиксируйте (`git commit -m "Add my feature"`)
4. Отправьте ветку (`git push origin feature/my-feature`)
5. Откройте Pull Request

## Лицензия

Проект распространяется под лицензией MIT — подробности в файле [LICENSE](LICENSE).

## Благодарности

- [3x-ui](https://github.com/mhsanaei/3x-ui) — панель управления Xray
- [Xray-core](https://github.com/XTLS/Xray-core) — ядро прокси-сервера (VLESS, Reality, XHTTP, Vision)
- [Happ](https://github.com/Happ-proxy) — кроссплатформенный клиент на базе Xray-core
