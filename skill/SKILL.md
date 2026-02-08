---
name: 3x-ui-setup
description: Complete VPN server setup from scratch. Takes a fresh VPS (IP + root + password from hosting provider) through full server hardening and 3x-ui (Xray proxy panel) installation with VLESS Reality or VLESS TLS. Guides user through connecting via Hiddify client. Use when user mentions v2ray, xray, vless, 3x-ui, proxy server, vpn server, or wants to set up encrypted proxy access on a VPS. Designed for beginners — hand-holds through every step.
allowed-tools: Bash,Read,Write,Edit
---

# VPN Server Setup (3x-ui)

Complete setup: fresh VPS from provider → secured server → working VPN with Hiddify client.

## Workflow Overview

```
ЧАСТЬ 1: Настройка сервера
  Fresh VPS (IP + root + password)
    → Determine execution mode (remote or local)
    → Generate SSH key / setup access
    → Connect as root
    → Update system
    → Create non-root user + sudo
    → Install SSH key
    → TEST new user login (critical!)
    → Disable root + password auth
    → Firewall (ufw)
    → fail2ban
    → Kernel hardening
    → Time sync + packages
    → Configure local ~/.ssh/config
    → ✅ Server secured

ЧАСТЬ 2: Установка VPN (3x-ui)
    → Install 3x-ui panel
    → Enable BBR (TCP optimization)
    → Disable ICMP (stealth)
    → Reality: scanner → create inbound → get link
    → Install Hiddify client
    → Verify connection
    → Generate guide file (credentials + instructions)
    → Finalize SSH access (local mode: lockdown last)
    → ✅ VPN working
```

---

# PART 1: Server Hardening

Secure a fresh server from provider credentials to production-ready state.

## Step 0: Collect Information

First, determine **execution mode**:

**Где запущен Claude Code?**
- **На локальном компьютере** (Remote mode) -- настраиваем удалённый сервер через SSH
- **На самом сервере** (Local mode) -- настраиваем этот же сервер напрямую

### Remote Mode -- ASK the user for:

1. **Server IP** -- from provider email
2. **Root password** -- from provider email
3. **Desired username** -- for the new non-root account
4. **Server nickname** -- for SSH config (e.g., `myserver`, `vpn1`)
5. **Has domain?** -- if unsure, recommend "no" (Reality path, simpler)
6. **Domain name** (if yes to #5) -- must already point to server IP

### Local Mode -- ASK the user for:

1. **Desired username** -- for the new non-root account
2. **Server nickname** -- for future SSH access from user's computer (e.g., `myserver`, `vpn1`)
3. **Has domain?** -- if unsure, recommend "no" (Reality path, simpler)
4. **Domain name** (if yes to #3) -- must already point to server IP

In Local mode, get server IP automatically:
```bash
curl -4 -s ifconfig.me
```

If user pastes the full provider email, extract the data from it.

**Recommend Reality (no domain) for beginners.** Explain:
- Reality: works without domain, free, simpler setup, great performance
- TLS: needs domain purchase (~$10/year), more traditional, allows fallback site

## Execution Modes

All commands in this skill are written for **Remote mode** (via SSH).
For **Local mode**, adapt as follows:

| Step | Remote Mode (default) | Local Mode |
|------|----------------------|------------|
| Step 1 | Generate SSH key on LOCAL machine | **SKIP** -- user creates key on laptop later (Step 22) |
| Step 2 | `ssh root@{SERVER_IP}` | Already on server. If not root: `sudo su -` |
| Steps 3-4 | Run on server via root SSH | Run directly (already on server) |
| Step 5 | Install local public key on server | **SKIP** -- user sends .pub via SCP later (Step 22) |
| Step 6 | SSH test from LOCAL: `ssh -i ... user@IP` | Switch user: `su - {username}`, then `sudo whoami` |
| Step 7 | Lock SSH via user session | **SKIP** -- keep password auth for SCP, lock at end (Step 22) |
| Steps 8-11 | `sudo` on server via SSH | `sudo` directly (no SSH prefix) |
| Step 12 | Write `~/.ssh/config` on LOCAL | **SKIP** -- user does this from guide file (Step 22) |
| Step 13 | Verify via `ssh {nickname}` | Run audit directly, **skip SSH lockdown checks** |
| Part 2 | `ssh {nickname} "sudo ..."` | `sudo ...` directly (no SSH prefix) |
| Panel access | Via SSH tunnel | Direct: `https://127.0.0.1:{panel_port}/{web_base_path}` |
| Step 22 | Generate guide file on LOCAL | Generate guide → SCP download → SSH key setup → lock SSH |

**IMPORTANT:** In both modes, the end result is the same -- user has SSH key access to the server from their local computer via `ssh {nickname}`, password auth disabled, root login disabled.

## Step 1: Generate SSH Key (LOCAL)

Run on the user's LOCAL machine BEFORE connecting to the server:

```bash
ssh-keygen -t ed25519 -C "{username}@{nickname}" -f ~/.ssh/{nickname}_key -N ""
```

Save the public key content for later:
```bash
cat ~/.ssh/{nickname}_key.pub
```

## Step 2: First Connection as Root

```bash
ssh root@{SERVER_IP}
```

### Handling forced password change

Many providers force a password change on first login. Signs:
- Prompt: "You are required to change your password immediately"
- Prompt: "Current password:" followed by "New password:"
- Prompt: "WARNING: Your password has expired"

If this happens:
1. Enter the current (provider) password
2. Enter a new strong temporary password (this is temporary -- SSH keys will replace it)
3. You may be disconnected -- reconnect with the new password

**If connection drops after password change -- this is normal.** Reconnect:
```bash
ssh root@{SERVER_IP}
```

## Step 3: System Update (as root on server)

```bash
apt update && DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=a apt upgrade -y
```

## Step 4: Create Non-Root User

```bash
useradd -m -s /bin/bash {username}
echo "{username}:{GENERATE_STRONG_PASSWORD}" | chpasswd
usermod -aG sudo {username}
```

Generate a strong random password. Tell the user to save it (needed for sudo). Then:

```bash
# Verify
groups {username}
```

## Step 5: Install SSH Key for New User

```bash
mkdir -p /home/{username}/.ssh
echo "{PUBLIC_KEY_CONTENT}" > /home/{username}/.ssh/authorized_keys
chmod 700 /home/{username}/.ssh
chmod 600 /home/{username}/.ssh/authorized_keys
chown -R {username}:{username} /home/{username}/.ssh
```

## Step 6: TEST New User Login -- CRITICAL CHECKPOINT

**DO NOT proceed without successful test!**

Open a NEW connection (keep root session alive):
```bash
ssh -i ~/.ssh/{nickname}_key {username}@{SERVER_IP}
```

Verify sudo works:
```bash
sudo whoami
# Must output: root
```

**If this fails** -- debug permissions, do NOT disable root login:
```bash
# Check on server as root:
ls -la /home/{username}/.ssh/
cat /home/{username}/.ssh/authorized_keys
# Fix ownership:
chown -R {username}:{username} /home/{username}/.ssh
```

## Step 7: Lock Down SSH

**Local Mode: SKIP this step entirely.** Password auth must stay enabled so user can download the guide file and upload their SSH public key via SCP later (Step 22). SSH lockdown happens at the very end.

Only after Step 6 succeeds (Remote Mode):

```bash
sudo sed -i 's/^#\?PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config
sudo sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config
sudo systemctl restart sshd
```

## Step 8: Firewall

```bash
sudo apt install -y ufw
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow ssh
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw --force enable
sudo ufw status
```

## Step 9: fail2ban

```bash
sudo apt install -y fail2ban
sudo tee /etc/fail2ban/jail.local << 'EOF'
[DEFAULT]
bantime = 1h
findtime = 10m
maxretry = 5

[sshd]
enabled = true
port = ssh
filter = sshd
logpath = /var/log/auth.log
maxretry = 3
bantime = 24h
EOF
sudo systemctl enable fail2ban
sudo systemctl restart fail2ban
```

## Step 10: Kernel Hardening

```bash
sudo tee /etc/sysctl.d/99-security.conf << 'EOF'
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.tcp_syncookies = 1
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
EOF
sudo sysctl -p /etc/sysctl.d/99-security.conf
```

## Step 11: Time Sync + Base Packages

```bash
sudo apt install -y chrony curl wget unzip net-tools
sudo systemctl enable chrony
```

## Step 12: Configure Local SSH Config

On the user's LOCAL machine:

```bash
cat >> ~/.ssh/config << 'EOF'

Host {nickname}
    HostName {SERVER_IP}
    User {username}
    IdentityFile ~/.ssh/{nickname}_key
    IdentitiesOnly yes
EOF
```

Tell user: **Теперь подключайся командой `ssh {nickname}` -- без пароля и IP.**

## Step 13: Final Verification

Connect as new user and run quick audit:
```bash
ssh {nickname}
# Then on server:
grep -E "PermitRootLogin|PasswordAuthentication" /etc/ssh/sshd_config
sudo ufw status
sudo systemctl status fail2ban --no-pager
sudo sysctl net.ipv4.conf.all.rp_filter
```

Expected: root login disabled, password auth disabled, ufw active, fail2ban running, rp_filter = 1.

**Local Mode:** Skip the `PermitRootLogin` and `PasswordAuthentication` checks -- they will still show default values since Step 7 was skipped. SSH lockdown happens in Step 22 after the user sets up their key.

**Part 1 complete. Server is secured. Proceeding to VPN installation.**

---

# PART 2: VPN Installation (3x-ui)

All commands from here use `ssh {nickname}` -- the shortcut configured in Part 1.

## Step 14: Install 3x-ui

3x-ui install script requires root. Run with sudo:

```bash
ssh {nickname} "curl -Ls https://raw.githubusercontent.com/mhsanaei/3x-ui/master/install.sh -o /tmp/3x-ui-install.sh && echo 'n' | sudo bash /tmp/3x-ui-install.sh"
```

The `echo 'n'` answers "no" to port customization prompt -- a random port and credentials will be generated.

**Note:** Do NOT use `sudo bash <(curl ...)` -- process substitution does not work with sudo (file descriptors are not inherited).

**IMPORTANT:** Capture the output! It contains:
- Generated **username**
- Generated **password**
- Panel **port**
- Panel **web base path**

Extract and save these values. Show them to the user:

```
Данные панели 3x-ui (СОХРАНИ!):
  Username: {panel_username}
  Password: {panel_password}
  Port:     {panel_port}
  Path:     {web_base_path}
  URL:      https://127.0.0.1:{panel_port}/{web_base_path} (через SSH-туннель)
```

Verify 3x-ui is running:

```bash
ssh {nickname} "sudo x-ui status"
```

If not running: `ssh {nickname} "sudo x-ui start"`

**Panel port is NOT opened in firewall intentionally** -- access panel only via SSH tunnel for security.

## Step 14b: Enable BBR

BBR (Bottleneck Bandwidth and RTT) dramatically improves TCP throughput, especially on lossy links -- critical for VPN performance.

```bash
ssh {nickname} 'current=$(sysctl -n net.ipv4.tcp_congestion_control); echo "Current: $current"; if [ "$current" != "bbr" ]; then echo "net.core.default_qdisc=fq" | sudo tee -a /etc/sysctl.conf && echo "net.ipv4.tcp_congestion_control=bbr" | sudo tee -a /etc/sysctl.conf && sudo sysctl -p && echo "BBR enabled"; else echo "BBR already active"; fi'
```

Verify:
```bash
ssh {nickname} "sysctl net.ipv4.tcp_congestion_control net.core.default_qdisc"
```

Expected: `net.ipv4.tcp_congestion_control = bbr`, `net.core.default_qdisc = fq`.

## Step 15: Disable ICMP (Stealth)

Makes server invisible to ping scans:

```bash
ssh {nickname} "sudo sed -i 's/-A ufw-before-input -p icmp --icmp-type echo-request -j ACCEPT/-A ufw-before-input -p icmp --icmp-type echo-request -j DROP/' /etc/ufw/before.rules && sudo sed -i 's/-A ufw-before-forward -p icmp --icmp-type echo-request -j ACCEPT/-A ufw-before-forward -p icmp --icmp-type echo-request -j DROP/' /etc/ufw/before.rules && sudo ufw reload"
```

Verify:
```bash
ping -c 2 -W 2 {SERVER_IP}
```

Expected: no response (timeout).

## Step 16: Branch -- Reality or TLS

### Path A: VLESS Reality (NO domain needed) -- RECOMMENDED

Go to Step 17A.

### Path B: VLESS TLS (domain required)

Go to `references/vless-tls.md`.

## Step 17A: Find Best SNI with Reality Scanner

Download and run Reality Scanner to find optimal SNI/Target for the server's network:

```bash
ssh {nickname} 'ARCH=$(dpkg --print-architecture); case "$ARCH" in amd64) SA="64";; arm64|aarch64) SA="arm64-v8a";; *) SA="$ARCH";; esac && curl -sL "https://github.com/XTLS/RealiTLScanner/releases/latest/download/RealiTLScanner-linux-${SA}" -o /tmp/scanner && chmod +x /tmp/scanner && file /tmp/scanner | grep -q ELF && timeout 30 /tmp/scanner --addr $(curl -4 -s ifconfig.me) 2>&1 | head -30 || echo "ERROR: scanner binary not valid for this architecture"'
```

**Note:** GitHub releases use non-standard arch names (`64` instead of `amd64`, `arm64-v8a` instead of `arm64`). The `case` block maps them. The `file | grep ELF` check ensures the download is a real binary, not a 404 HTML page.

Look for well-known domains (github.com, microsoft.com, twitch.tv, etc.) in the output.

**If scanner finds nothing or times out** -- use a reliable fallback SNI: `yahoo.com`, `www.microsoft.com`, or `www.google.com`. Some hosting providers (e.g., OVH) have subnets where the scanner finds no nearby TLS servers -- this is normal, fallback SNI will work.

Save the best SNI (e.g., `github.com`) for the next step.

## Step 18A: Create VLESS Reality Inbound via API

**Pre-check:** Verify port 443 is not occupied by another service (some providers pre-install apache2/nginx):

```bash
ssh {nickname} "ss -tlnp | grep ':443 '"
```

If something is listening on 443, stop and disable it first (e.g., `sudo systemctl stop apache2 && sudo systemctl disable apache2`). Otherwise the VLESS inbound will silently fail to bind.

3x-ui has an API. Since v2.8+, the installer auto-configures SSL, so the panel runs on HTTPS. Use `-k` to skip certificate verification (self-signed cert on localhost).

First, get session cookie:

```bash
ssh {nickname} 'PANEL_PORT={panel_port}; curl -sk -c /tmp/3x-cookie -b /tmp/3x-cookie -X POST "https://127.0.0.1:${PANEL_PORT}/{web_base_path}/login" -H "Content-Type: application/x-www-form-urlencoded" -d "username={panel_username}&password={panel_password}"'
```

Generate keys for Reality:

```bash
ssh {nickname} "sudo /usr/local/x-ui/bin/xray-linux-* x25519"
```

This outputs two lines: `PrivateKey` = private key, `Password` = **public key** (confusing naming by xray). Save both.

Generate UUID for the client:

```bash
ssh {nickname} "sudo /usr/local/x-ui/bin/xray-linux-* uuid"
```

Generate random Short ID:

```bash
ssh {nickname} "openssl rand -hex 8"
```

Create the inbound:

```bash
ssh {nickname} 'PANEL_PORT={panel_port}; curl -sk -c /tmp/3x-cookie -b /tmp/3x-cookie -X POST "https://127.0.0.1:${PANEL_PORT}/{web_base_path}/panel/api/inbounds/add" -H "Content-Type: application/json" -d '"'"'{
  "up": 0,
  "down": 0,
  "total": 0,
  "remark": "vless-reality",
  "enable": true,
  "expiryTime": 0,
  "listen": "",
  "port": 443,
  "protocol": "vless",
  "settings": "{\"clients\":[{\"id\":\"{CLIENT_UUID}\",\"flow\":\"xtls-rprx-vision\",\"email\":\"user1\",\"limitIp\":0,\"totalGB\":0,\"expiryTime\":0,\"enable\":true}],\"decryption\":\"none\",\"fallbacks\":[]}",
  "streamSettings": "{\"network\":\"tcp\",\"security\":\"reality\",\"externalProxy\":[],\"realitySettings\":{\"show\":false,\"xver\":0,\"dest\":\"{BEST_SNI}:443\",\"serverNames\":[\"{BEST_SNI}\"],\"privateKey\":\"{PRIVATE_KEY}\",\"minClient\":\"\",\"maxClient\":\"\",\"maxTimediff\":0,\"shortIds\":[\"{SHORT_ID}\"],\"settings\":{\"publicKey\":\"{PUBLIC_KEY}\",\"fingerprint\":\"chrome\",\"serverName\":\"\",\"spiderX\":\"/\"}},\"tcpSettings\":{\"acceptProxyProtocol\":false,\"header\":{\"type\":\"none\"}}}",
  "sniffing": "{\"enabled\":true,\"destOverride\":[\"http\",\"tls\",\"quic\",\"fakedns\"],\"metadataOnly\":false,\"routeOnly\":false}",
  "allocate": "{\"strategy\":\"always\",\"refresh\":5,\"concurrency\":3}"
}'"'"''
```

**If API approach fails** -- tell user to access panel via SSH tunnel (Step 18A-alt).

### Step 18A-alt: SSH Tunnel to Panel (manual fallback)

If API fails, user can access panel in browser:

```bash
ssh -L {panel_port}:127.0.0.1:{panel_port} {nickname}
```

Then open in browser: `https://127.0.0.1:{panel_port}/{web_base_path}` (browser will warn about self-signed cert -- accept it)

Guide user through the UI:
1. Login with generated credentials
2. Inbounds -> Add Inbound
3. Protocol: VLESS
4. Port: 443
5. Security: Reality
6. Client Flow: xtls-rprx-vision
7. Target & SNI: paste the best SNI from scanner
8. Click "Get New Cert" for keys
9. Create

## Step 19: Get Connection Link

Get the client connection link from 3x-ui API:

```bash
ssh {nickname} 'PANEL_PORT={panel_port}; curl -sk -b /tmp/3x-cookie "https://127.0.0.1:${PANEL_PORT}/{web_base_path}/panel/api/inbounds/list" | python3 -c "
import json,sys
data = json.load(sys.stdin)
for inb in data.get(\"obj\", []):
    if inb.get(\"protocol\") == \"vless\":
        settings = json.loads(inb[\"settings\"])
        stream = json.loads(inb[\"streamSettings\"])
        client = settings[\"clients\"][0]
        uuid = client[\"id\"]
        port = inb[\"port\"]
        security = stream.get(\"security\", \"none\")
        if security == \"reality\":
            rs = stream[\"realitySettings\"]
            sni = rs[\"serverNames\"][0]
            pbk = rs[\"settings\"][\"publicKey\"]
            sid = rs[\"shortIds\"][0]
            fp = rs[\"settings\"].get(\"fingerprint\", \"chrome\")
            flow = client.get(\"flow\", \"\")
            link = f\"vless://{uuid}@$(curl -4 -s ifconfig.me):{port}?type=tcp&security=reality&pbk={pbk}&fp={fp}&sni={sni}&sid={sid}&spx=%2F&flow={flow}#vless-reality\"
            print(link)
            break
"'
```

**Show the link to the user.** This is what they'll paste into Hiddify.

**IMPORTANT: Terminal line-wrap fix.** Long VLESS links break when copied from terminal. ALWAYS provide the link in TWO formats:

1. The raw link (for reference)
2. A ready-to-copy block with LLM cleanup prompt:

~~~
Скопируй всё ниже и вставь в любой LLM (ChatGPT, Claude) чтобы получить чистую ссылку:

Убери все переносы строк и лишние пробелы из этой ссылки, выдай одной строкой:

{VLESS_LINK}
~~~

Also save the link to a file for easy access:

```bash
ssh {nickname} "echo '{VLESS_LINK}' > ~/vpn-link.txt"
```

Tell the user: **Ссылка также сохранена в файл ~/vpn-link.txt**

Cleanup session cookie:
```bash
ssh {nickname} "rm -f /tmp/3x-cookie"
```

## Step 20: Guide User -- Install Hiddify Client

Tell the user:

```
Теперь установи клиент Hiddify на своё устройство:

Android:  Google Play -> "Hiddify" или https://github.com/hiddify/hiddify-app/releases
iOS:      App Store -> "Hiddify"
Windows:  https://github.com/hiddify/hiddify-app/releases (скачай .exe)
macOS:    https://github.com/hiddify/hiddify-app/releases (скачай .dmg)
Linux:    https://github.com/hiddify/hiddify-app/releases (.deb или .AppImage)

После установки:
1. Открой Hiddify
2. Нажми "+" или "Add Profile"
3. Выбери "Add from clipboard" (ссылка уже скопирована)
4. Или отсканируй QR-код (я могу его показать)
5. Нажми кнопку подключения (большая кнопка в центре)
6. Готово! Проверь IP на сайте: https://2ip.ru
```

## Step 21: Verify Connection Works

After user connects via Hiddify, verify:

```bash
ssh {nickname} "sudo x-ui status && ss -tlnp | grep -E '443|{panel_port}'"
```

## Step 22: Generate Guide File & Finalize SSH Access

This step generates a comprehensive guide file with all credentials and instructions, then finalizes SSH key-based access.

### Remote Mode

In Remote mode, SSH is already secured (Steps 1, 5, 7, 12). Generate the guide file on the user's LOCAL machine:

**22R: Generate guide file locally**

Use the **Write tool** to create `~/vpn-{nickname}-guide.md` on the user's local machine. Use the **Guide File Template** below, substituting all `{variables}` with actual values.

Tell user: **Методичка сохранена в ~/vpn-{nickname}-guide.md -- там все пароли, доступы и инструкции.**

### Local Mode

In Local mode, Claude Code runs on the server. SSH lockdown was skipped (Step 7), so password auth still works. The flow:

#### 22L-1: Generate guide file on server

Use the **Write tool** to create `/home/{username}/vpn-guide.md` on the server. Use the **Guide File Template** below, substituting all `{variables}` with actual values.

#### 22L-2: User downloads guide via SCP

Tell the user:

```
Методичка готова! Скачай её на свой компьютер.
Открой НОВЫЙ терминал на своём ноутбуке и выполни:

scp {username}@{SERVER_IP}:~/vpn-guide.md ./

Пароль: {sudo_password}

Файл сохранится в текущую папку. Открой его -- там все пароли и инструкции.
```

**Fallback:** If SCP doesn't work (Windows without OpenSSH, network issues), show the full guide content directly in chat.

#### 22L-3: User creates SSH key on their laptop

Tell the user:

```
Теперь создай SSH-ключ на своём компьютере.
Есть два варианта:

Вариант А: Следуй инструкциям из раздела "SSH Key Setup" в методичке.

Вариант Б (автоматический): Установи Claude Code на ноутбуке
  (https://claude.ai/download) и скинь ему файл vpn-guide.md --
  он сам всё настроит по инструкциям из раздела "Instructions for Claude Code".

После создания ключа отправь публичный ключ на сервер (следующий шаг).
```

#### 22L-4: User sends public key to server via SCP

Tell the user:

```
Отправь публичный ключ на сервер (из терминала на ноутбуке):

scp ~/.ssh/{nickname}_key.pub {username}@{SERVER_IP}:~/

Пароль: {sudo_password}
```

Wait for user confirmation before proceeding.

#### 22L-5: Install key + verify

```bash
mkdir -p /home/{username}/.ssh
cat /home/{username}/{nickname}_key.pub >> /home/{username}/.ssh/authorized_keys
chmod 700 /home/{username}/.ssh
chmod 600 /home/{username}/.ssh/authorized_keys
chown -R {username}:{username} /home/{username}/.ssh
rm -f /home/{username}/{nickname}_key.pub
```

Tell user to test from their laptop:
```
Проверь подключение с ноутбука:
ssh -i ~/.ssh/{nickname}_key {username}@{SERVER_IP}

Должно подключиться без пароля.
```

**Wait for user confirmation that SSH key works before proceeding!**

#### 22L-6: Lock down SSH

**Only after user confirms key-based login works:**

```bash
sudo sed -i 's/^#\?PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config
sudo sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config
sudo systemctl restart sshd
```

Verify:
```bash
grep -E "PermitRootLogin|PasswordAuthentication" /etc/ssh/sshd_config
```

Expected: `PermitRootLogin no`, `PasswordAuthentication no`.

#### 22L-7: User configures SSH config

Tell the user:

```
Последний шаг! Добавь на ноутбуке в файл ~/.ssh/config:

Host {nickname}
    HostName {SERVER_IP}
    User {username}
    IdentityFile ~/.ssh/{nickname}_key
    IdentitiesOnly yes

Теперь подключайся просто: ssh {nickname}
```

#### 22L-8: Delete guide file from server

```bash
rm -f /home/{username}/vpn-guide.md
```

Tell user: **Методичка удалена с сервера. Убедись, что она сохранена на твоём компьютере.**

---

### Guide File Template

Generate this file using the **Write tool**, substituting all `{variables}` with actual values collected during setup.

~~~markdown
# VPN Server Guide — {nickname}

Generated: {current_date}

## 1. Server Connection

| Field | Value |
|-------|-------|
| IP | `{SERVER_IP}` |
| Username | `{username}` |
| Sudo password | `{sudo_password}` |
| SSH key | `~/.ssh/{nickname}_key` |
| Quick connect | `ssh {nickname}` |

## 2. 3x-ui Panel

| Field | Value |
|-------|-------|
| URL | `https://127.0.0.1:{panel_port}/{web_base_path}` |
| Login | `{panel_username}` |
| Password | `{panel_password}` |

Access via SSH tunnel:
```
ssh -L {panel_port}:127.0.0.1:{panel_port} {nickname}
```
Then open: `https://127.0.0.1:{panel_port}/{web_base_path}`

## 3. VPN Connection

| Field | Value |
|-------|-------|
| Protocol | VLESS Reality |
| Port | 443 |
| SNI | `{best_sni}` |
| Client | Hiddify |

VLESS link:
```
{VLESS_LINK}
```

## 4. SSH Key Setup

If you don't have an SSH key yet, follow the instructions for your OS:

### macOS / Linux

```bash
# Generate key
ssh-keygen -t ed25519 -C "{username}@{nickname}" -f ~/.ssh/{nickname}_key -N ""

# Send public key to server
scp ~/.ssh/{nickname}_key.pub {username}@{SERVER_IP}:~/

# Set permissions
chmod 600 ~/.ssh/{nickname}_key

# Add to SSH config
cat >> ~/.ssh/config << 'SSHEOF'

Host {nickname}
    HostName {SERVER_IP}
    User {username}
    IdentityFile ~/.ssh/{nickname}_key
    IdentitiesOnly yes
SSHEOF

# Test connection
ssh {nickname}
```

### Windows (PowerShell)

```powershell
# Generate key
ssh-keygen -t ed25519 -C "{username}@{nickname}" -f $HOME\.ssh\{nickname}_key -N '""'

# Send public key to server
scp $HOME\.ssh\{nickname}_key.pub {username}@{SERVER_IP}:~/

# Add to SSH config
Add-Content $HOME\.ssh\config @"

Host {nickname}
    HostName {SERVER_IP}
    User {username}
    IdentityFile ~/.ssh/{nickname}_key
    IdentitiesOnly yes
"@

# Test connection
ssh {nickname}
```

Note: `chmod` is not needed on Windows. SSH uses ACLs automatically.

## 5. Common Operations

```bash
ssh {nickname}                           # connect to server
ssh {nickname} "sudo x-ui status"        # panel status
ssh {nickname} "sudo x-ui restart"       # restart panel
ssh {nickname} "sudo x-ui log"           # view logs
ssh {nickname} "sudo x-ui setting -reset" # reset panel password
```

Add new VPN client:
Open panel via SSH tunnel → Inbounds → ... → Add Client → share link/QR.

## 6. Security Status

| Feature | Status |
|---------|--------|
| Root login | Disabled |
| Password auth | Disabled |
| UFW firewall | Enabled (SSH, 80, 443) |
| fail2ban | Enabled (3 attempts → 24h ban) |
| Kernel hardening | Enabled (sysctl) |
| BBR | Enabled |
| ICMP (ping) | Disabled |

## 7. Troubleshooting

| Problem | Solution |
|---------|----------|
| Connection refused | `ssh {nickname} "sudo x-ui status"` — restart if stopped |
| Permission denied (publickey) | Check key path and permissions: `ls -la ~/.ssh/{nickname}_key` |
| Host key verification failed | `ssh-keygen -R {SERVER_IP}` then reconnect |
| Panel not accessible | Use SSH tunnel (see section 2) |
| VPN not connecting | Wrong SNI or server down — check `sudo x-ui log` |
| Forgot panel password | `ssh {nickname} "sudo x-ui setting -reset"` |

## 8. Instructions for Claude Code

This section is for automated setup by Claude Code running on your local computer.
Copy everything below and paste it to Claude Code on your laptop.

---

**TASK: Set up SSH key access to VPN server**

Server data:
- SERVER_IP: {SERVER_IP}
- USERNAME: {username}
- PASSWORD: {sudo_password}
- NICKNAME: {nickname}

Steps:
1. Generate SSH key: `ssh-keygen -t ed25519 -C "{username}@{nickname}" -f ~/.ssh/{nickname}_key -N ""`
2. Send public key to server: `scp ~/.ssh/{nickname}_key.pub {username}@{SERVER_IP}:~/`
   (use password above when prompted)
3. SSH to server and install the key:
   ```
   ssh {username}@{SERVER_IP} 'mkdir -p ~/.ssh && cat ~/{nickname}_key.pub >> ~/.ssh/authorized_keys && chmod 700 ~/.ssh && chmod 600 ~/.ssh/authorized_keys && rm ~/{nickname}_key.pub'
   ```
4. Test key-based login: `ssh -i ~/.ssh/{nickname}_key {username}@{SERVER_IP}` (should work without password)
5. Add SSH config:
   ```
   cat >> ~/.ssh/config << 'EOF'

   Host {nickname}
       HostName {SERVER_IP}
       User {username}
       IdentityFile ~/.ssh/{nickname}_key
       IdentitiesOnly yes
   EOF
   ```
6. Verify: `ssh {nickname}` (should connect without password)
7. Tell the user: "SSH key configured. Connect with: ssh {nickname}"
~~~

---

## Completion Summary

Print this summary for the user:

```
VPN-сервер полностью настроен и работает!

Подключение к серверу:
   Команда:     ssh {nickname}
   IP:          {SERVER_IP}
   Пользователь: {username}
   SSH-ключ:    ~/.ssh/{nickname}_key
   Пароль sudo: {sudo_password}

Безопасность сервера:
   Root-вход отключён
   Парольный вход отключён
   Файрвол включён (порты: SSH, 80, 443)
   fail2ban защищает от брутфорса
   Ядро усилено (sysctl)
   BBR включён (TCP-оптимизация)
   ICMP отключён (сервер не пингуется)

Панель 3x-ui:
   URL:      https://127.0.0.1:{panel_port}/{web_base_path} (через SSH-туннель)
   Login:    {panel_username}
   Password: {panel_password}

VPN-подключение:
   Протокол:  VLESS Reality
   Порт:      443
   SNI:       {best_sni}

Клиент:
   Hiddify -- ссылка добавлена

Управление (через SSH):
   ssh {nickname}                           # подключиться к серверу
   ssh {nickname} "sudo x-ui status"        # статус панели
   ssh {nickname} "sudo x-ui restart"       # перезапустить панель
   ssh {nickname} "sudo x-ui log"           # логи

SSH-туннель к админке:
   ssh -L {panel_port}:127.0.0.1:{panel_port} {nickname}
   Затем открыть: https://127.0.0.1:{panel_port}/{web_base_path}

Добавить нового клиента:
   Открой админку -> Inbounds -> ... -> Add Client
   Скинь ссылку или QR-код другому человеку

Методичка: ~/vpn-{nickname}-guide.md
   Все пароли, инструкции и команды в одном файле
```

## Critical Rules

### Part 1 (Server)
1. **NEVER skip Step 6** (test login) -- user can be locked out permanently
2. **NEVER disable root before confirming new user works**
3. **NEVER store passwords in files** -- only display once to user
4. **If connection drops** after password change -- reconnect, this is normal
5. **If Step 6 fails** -- fix it before proceeding, keep root session open
6. **Generate SSH key BEFORE first connection** -- more efficient workflow
7. **All operations after Step 7 use sudo** -- not root

### Part 2 (VPN)
8. **NEVER expose panel to internet** -- access only via SSH tunnel
9. **NEVER skip firewall configuration** -- only open needed ports
10. **ALWAYS save panel credentials** -- show them once, clearly
11. **ALWAYS verify connection works** before declaring success
12. **Ask before every destructive or irreversible action**
13. **ALWAYS generate guide file** (Step 22) -- the user's single source of truth
14. **Local Mode: do NOT lock SSH in Step 7** -- keep password auth until Step 22
15. **Local Mode: lock SSH LAST** (Step 22L-6) -- only after user confirms key works
16. **NEVER leave password auth enabled** after setup is complete

## Troubleshooting

| Problem | Solution |
|---------|----------|
| Connection drops after password change | Normal -- reconnect with new password |
| Permission denied (publickey) | Check key path and permissions (700/600) |
| Host key verification failed | `ssh-keygen -R {SERVER_IP}` then reconnect |
| x-ui install fails | `sudo apt update && sudo apt install -y curl tar` |
| Panel not accessible | Use SSH tunnel: `ssh -L {panel_port}:127.0.0.1:{panel_port} {nickname}` |
| Reality not connecting | Wrong SNI -- re-run scanner, try different domain |
| Hiddify shows error | Update Hiddify to latest version, re-add link |
| "connection refused" | Check x-ui is running: `sudo x-ui status` |
| Forgot panel password | `sudo x-ui setting -reset` |
| SCP fails (Windows) | Install OpenSSH: Settings → Apps → Optional Features → OpenSSH Client |
| SCP fails (connection refused) | Check UFW allows SSH: `sudo ufw status`, verify sshd running |
| BBR not active after reboot | Re-check: `sysctl net.ipv4.tcp_congestion_control` -- re-apply if needed |

## x-ui CLI Reference

```bash
x-ui start          # start panel
x-ui stop           # stop panel
x-ui restart        # restart panel
x-ui status         # check status
x-ui setting -reset # reset username/password
x-ui log            # view logs
x-ui cert           # manage SSL certificates
x-ui update         # update to latest version
```
