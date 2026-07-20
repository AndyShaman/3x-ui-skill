# 3x-ui-setup

**Claude Code skill for automated VPN server deployment**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE) ![Platform](https://img.shields.io/badge/Platform-Linux%20VPS-orange) ![Claude Code](https://img.shields.io/badge/Claude%20Code-Skill-blueviolet)

> **Русская версия**: [README.ru.md](README.ru.md)

## Quick Install

```bash
curl -fsSL https://raw.githubusercontent.com/AndyShaman/3x-ui-skill/main/install.sh | bash
```

Or manually:

```bash
git clone https://github.com/AndyShaman/3x-ui-skill.git
cp -r 3x-ui-skill/skill ~/.claude/skills/3x-ui-setup
rm -rf 3x-ui-skill
```

## Overview

A Claude Code skill that fully automates VPN server deployment on a fresh VPS. Hand it your server IP and root password — it handles everything from OS hardening to two VLESS+Reality profiles (XHTTP + TCP/Vision) delivered as a single subscription link, with Happ client setup.

Built for beginners who want a secure, censorship-resistant connection without learning sysadmin or proxy protocols. Tuned for the Russian 2026 DPI landscape. The skill walks through each step, verifies critical checkpoints, and leaves you with a hardened server and a ready-to-use VPN.

## Features

- 🔒 **Full server hardening** — SSH keys, firewall (UFW), fail2ban (systemd backend), kernel tweaks
- 📦 **3x-ui panel** — randomized credentials, bound to loopback (SSH-tunnel access only)
- ⚡ **Two VLESS+Reality inbounds** — XHTTP (best DPI resistance) + TCP/Vision+padding (iOS + fallback)
- 🔗 **One subscription link** — both profiles, auto-updating, served over HTTPS
- 🌐 **VLESS TLS** — optional path with domain + auto SSL via acme.sh
- 🎭 **Nginx fallback page** — benign camouflage site for the TLS path
- 📱 **Happ client guidance** — step-by-step connection on any device
- 🇷🇺 **Tuned for RU 2026 DPI** — firefox fingerprint, Vision padding, honest whitelist docs
- 🖥️ **Remote or local mode** — works over SSH from your machine or directly on the server
- ✅ **Checkpoint-driven workflow** — key access verified before SSH lockdown
- 👻 **ICMP disabled** — server does not respond to ping for stealth

## Workflow

```
Fresh VPS (IP + root + password)
  |
  +-- Part 1: Server Hardening
  |   +-- SSH key generation
  |   +-- System update
  |   +-- Non-root user + sudo
  |   +-- Install SSH key (user AND root) + TEST key login
  |   +-- UFW firewall
  |   +-- Kernel hardening
  |   +-- SSH config shortcut
  |
  +-- Part 2: VPN Installation
  |   +-- 3x-ui panel install (loopback only) + BBR
  |   +-- ICMP disabled
  |   +-- Two VLESS+Reality inbounds (XHTTP 443 + TCP/Vision 8443)
  |   +-- Subscription server + LE cert on IP
  |   +-- Happ client setup + verify
  |
  +-- Finalize (LAST, after key verified)
  |   +-- fail2ban (systemd)
  |   +-- SSH lockdown (no root, no passwords)
  |
  +-- Done: Secured server + Working VPN
```

## What's Included

| File | Description |
|------|-------------|
| `skill/SKILL.md` | Main skill — orchestration spine |
| `skill/references/reality-inbound.md` | SNI scanner + both VLESS+Reality inbounds (XHTTP + TCP/Vision) |
| `skill/references/subscription.md` | Subscription server + LE cert on bare IP + panel tunnel |
| `skill/references/client-happ.md` | Happ install, import, connect, troubleshoot |
| `skill/references/finalize-hardening.md` | fail2ban + SSH lockdown with key-verify gate |
| `skill/references/guide-template.md` | Personal guide file + secrets policy |
| `skill/references/whitelist-and-fallbacks.md` | RU DPI expectations, fallback ladder, SNI pool |
| `skill/references/local-mode.md` | Deltas when Claude Code runs on the VPS |
| `skill/references/vless-tls.md` | Optional VLESS TLS path (domain required) |
| `skill/references/fallback-nginx.md` | Optional benign stub site for the TLS path |
| `install.sh` | One-line installer script |

## Supported Protocols

| Feature | VLESS Reality | VLESS TLS |
|---------|:------------:|:---------:|
| Domain required | No | Yes |
| SSL certificate | Not needed | Auto (acme.sh) |
| Difficulty | Easy | Medium |
| Fallback page | Built-in (target site) | Optional (Nginx) |
| Recommended for | Beginners | Advanced users |

## Usage

After installation, open Claude Code and say:

- *"Set up a VPN on my VPS"*
- *"I have a new server, help me configure VLESS"*
- *"Harden my server and install 3x-ui"*

The skill activates automatically when Claude detects a relevant request.

## Requirements

- [Claude Code](https://docs.anthropic.com/en/docs/claude-code) (CLI)
- Fresh VPS (Ubuntu/Debian) with root access
- SSH access from your machine
- *(Optional)* Domain name — only needed for the TLS path

## Troubleshooting

| Problem | Solution |
|---------|----------|
| `Permission denied (publickey)` | Check SSH key permissions: `chmod 700 ~/.ssh && chmod 600 ~/.ssh/*` |
| `Host key verification failed` | Remove old key: `ssh-keygen -R <server-ip>` |
| Panel not accessible in browser | Use SSH tunnel: `ssh -L <panel_port>:127.0.0.1:<panel_port> <nickname>` (the panel port is randomized at install) |
| Reality not connecting | Re-run the SNI scanner to find a working target |
| iOS connects but no internet | Use the TCP/8443 profile, not XHTTP (XHTTP+Reality is broken on Happ iOS) |
| Works on Wi-Fi, dead on mobile data | Whitelist region — a foreign VPS cannot help; see `whitelist-and-fallbacks.md` |
| Forgot panel password | Reset on server: `sudo x-ui setting -reset` |

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/improvement`)
3. Make your changes
4. Submit a pull request

## License

MIT — see [LICENSE](LICENSE) for details.

## Credits

Built on top of these projects:

- [3x-ui](https://github.com/mhsanaei/3x-ui) — Xray panel with multi-protocol support
- [Xray-core](https://github.com/XTLS/Xray-core) — the proxy engine behind VLESS, Reality, XHTTP, Vision
- [Happ](https://github.com/Happ-proxy) — Xray-core-based cross-platform proxy client
