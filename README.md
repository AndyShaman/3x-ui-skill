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

A Claude Code skill that fully automates VPN server deployment on a fresh VPS. Hand it your server IP and root password — it handles everything from OS hardening to a working VLESS proxy with client setup instructions.

Built for beginners who want a secure, censorship-resistant connection without learning sysadmin or proxy protocols. The skill walks through each step, verifies critical checkpoints, and leaves you with a hardened server and a ready-to-use VPN.

## Features

- 🔒 **Full server hardening** — SSH keys, firewall (UFW), fail2ban, kernel tweaks
- 📦 **3x-ui panel** — installed with randomized credentials and secure defaults
- ⚡ **VLESS Reality** — recommended path, no domain needed
- 🌐 **VLESS TLS** — alternative path with domain + auto SSL via acme.sh
- 🎭 **Nginx fallback page** — camouflage for the TLS path
- 📱 **Hiddify client guidance** — step-by-step connection on any device
- 🖥️ **Remote or local mode** — works over SSH from your machine or directly on the server
- ✅ **Checkpoint-driven workflow** — every critical step is verified before moving on
- 👻 **ICMP disabled** — server does not respond to ping for stealth

## Workflow

```
Fresh VPS (IP + root + password)
  |
  +-- Part 1: Server Hardening
  |   +-- SSH key generation
  |   +-- System update
  |   +-- Non-root user + sudo
  |   +-- SSH lockdown (no root, no passwords)
  |   +-- UFW firewall
  |   +-- fail2ban
  |   +-- Kernel hardening
  |   +-- SSH config shortcut
  |
  +-- Part 2: VPN Installation
  |   +-- 3x-ui panel install
  |   +-- ICMP disabled
  |   +-- Protocol setup (Reality or TLS)
  |   +-- Connection link generation
  |   +-- Hiddify client setup
  |
  +-- Done: Secured server + Working VPN
```

## What's Included

| File | Description |
|------|-------------|
| `skill/SKILL.md` | Main skill — complete setup automation |
| `skill/references/vless-tls.md` | VLESS TLS setup path (domain required) |
| `skill/references/fallback-nginx.md` | Nginx fallback page configuration for TLS |
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
| Panel not accessible in browser | Use SSH tunnel: `ssh -L 2053:localhost:2053 user@server` |
| Reality not connecting | Re-run the SNI scanner to find a working target |
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
- [Xray-core](https://github.com/XTLS/Xray-core) — the proxy engine behind VLESS, Reality, and more
- [Hiddify](https://github.com/hiddify/hiddify-app) — cross-platform proxy client
