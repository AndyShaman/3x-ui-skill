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
    → Firewall (ufw)
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
    → Install fail2ban + lock SSH (after key verified)
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
| Step 7 | **SKIP** -- lockdown deferred to Step 22 | **SKIP** -- lockdown deferred to Step 22 |
| Steps 8-11 | `sudo` on server via SSH | `sudo` directly (no SSH prefix) |
| Step 12 | Write `~/.ssh/config` on LOCAL | **SKIP** -- user does this from guide file (Step 22) |
| Step 13 | Verify via `ssh {nickname}` | Run audit directly, **skip SSH lockdown checks** |
| Part 2 | `ssh {nickname} "sudo ..."` | `sudo ...` directly (no SSH prefix) |
| Step 17A | Scanner via `ssh {nickname} '...'` | Scanner runs directly (no SSH wrapper) -- see Step 17A for both commands |
| Panel access | Via SSH tunnel | Direct: `https://127.0.0.1:{panel_port}/{web_base_path}` |
| Step 22 | Generate guide + fail2ban + lock SSH | Generate guide → SCP download → SSH key setup → fail2ban + lock SSH |

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

## Step 7: Lock Down SSH — DEFERRED

**Оба режима: ПРОПУСКАЕМ.** Блокировка SSH и установка fail2ban выполняются в самом конце (Step 22), после того как SSH-ключ проверен. Это предотвращает случайную блокировку доступа во время настройки.

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

## Step 9: fail2ban — DEFERRED

**Пропущен.** fail2ban устанавливается в конце настройки (Step 22) вместе с блокировкой SSH, чтобы не заблокировать пользователя во время настройки.

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
sudo ufw status
sudo sysctl net.ipv4.conf.all.rp_filter
```

Expected: ufw active, rp_filter = 1.

**Note:** SSH lockdown и fail2ban проверяются в конце (Step 22) после подтверждения работы SSH-ключа.

**Часть 1 завершена. Базовая настройка сервера готова. Переходим к установке VPN.**

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

Scan the server's **/24 subnet** to find real websites on neighboring IPs that support **TLS 1.3, H2 (HTTP/2), and X25519** -- the exact stack Reality needs to mimic a genuine TLS handshake. The found domain becomes the masquerade target (SNI/dest), making VPN traffic indistinguishable from regular HTTPS to a neighboring site on the same hosting.

**Why subnet scanning matters:**
- Reality reproduces a real TLS 1.3 handshake with the dest server -- the dest **must** support TLS 1.3 + H2 + X25519, or Reality won't work
- RealiTLScanner (from the XTLS project) checks exactly this -- it only outputs servers compatible with Reality
- DPI sees the SNI in TLS ClientHello and can probe the IP to verify the domain actually lives there
- Popular domains (microsoft.com, google.com) are often on CDN IPs far from the VPS -- active probing catches this
- A small unknown site on a neighboring IP (e.g., `shop.finn-auto.fi`) is ideal -- nobody filters it, and it's in the same subnet
- **Do NOT manually pick an SNI** without the scanner -- a random domain may not support TLS 1.3 or may be on a different IP range

Download and run Reality Scanner against the /24 subnet:

**Remote mode** (Claude Code on user's laptop):
```bash
ssh {nickname} 'ARCH=$(dpkg --print-architecture); case "$ARCH" in amd64) SA="64";; arm64|aarch64) SA="arm64-v8a";; *) SA="$ARCH";; esac && curl -sL "https://github.com/XTLS/RealiTLScanner/releases/latest/download/RealiTLScanner-linux-${SA}" -o /tmp/scanner && chmod +x /tmp/scanner && file /tmp/scanner | grep -q ELF || { echo "ERROR: scanner binary not valid for this architecture"; exit 1; }; MY_IP=$(curl -4 -s ifconfig.me); SUBNET=$(echo $MY_IP | sed "s/\.[0-9]*$/.0\/24/"); echo "Scanning subnet: $SUBNET"; timeout 120 /tmp/scanner --addr "$SUBNET" 2>&1 | head -80'
```

**Local mode** (Claude Code on the VPS itself):
```bash
ARCH=$(dpkg --print-architecture); case "$ARCH" in amd64) SA="64";; arm64|aarch64) SA="arm64-v8a";; *) SA="$ARCH";; esac && curl -sL "https://github.com/XTLS/RealiTLScanner/releases/latest/download/RealiTLScanner-linux-${SA}" -o /tmp/scanner && chmod +x /tmp/scanner && file /tmp/scanner | grep -q ELF || { echo "ERROR: scanner binary not valid for this architecture"; exit 1; }; MY_IP=$(curl -4 -s ifconfig.me); SUBNET=$(echo $MY_IP | sed "s/\.[0-9]*$/.0\/24/"); echo "Scanning subnet: $SUBNET"; timeout 120 /tmp/scanner --addr "$SUBNET" 2>&1 | head -80
```

**Note:** The commands are identical — Local mode simply runs without the `ssh {nickname}` wrapper since Claude Code is already on the VPS. GitHub releases use non-standard arch names (`64` instead of `amd64`, `arm64-v8a` instead of `arm64`). The `case` block maps them. The `file | grep ELF` check ensures the download is a real binary, not a 404 HTML page. Timeout is 120s because scanning 254 IPs takes longer than a single IP.

### Choosing the best SNI from scan results

Every domain in the scanner output already supports TLS 1.3 + H2 + X25519 (the scanner filters for this). From those results, **prefer** domains in this order:

1. **Small unknown sites on neighboring IPs** (e.g., `shop.finn-auto.fi`, `portal.company.de`) -- ideal, not filtered by DPI
2. **Regional/niche services** (e.g., local hosting panels, small business sites) -- low profile
3. **Well-known tech sites** (e.g., `github.com`, `twitch.tv`) -- acceptable but less ideal

**AVOID** these as SNI:
- `www.google.com`, `www.microsoft.com`, `googletagmanager.com` -- commonly blacklisted by DPI, people in Amnezia chats report these stop working
- Any domain behind a CDN (Cloudflare, Akamai, Fastly) -- the IP won't match the CDN edge, active probing detects this
- Domains that resolve to a completely different IP range than the VPS

**How to verify a candidate SNI:** The scanner output shows which IP responded with which domain. Pick a domain where the responding IP is in the same /24 as the VPS.

**If scanner finds nothing or times out** -- some providers (e.g., OVH) have sparse subnets. Try scanning a wider range `/23` (512 IPs):

**Remote mode:**
```bash
ssh {nickname} 'MY_IP=$(curl -4 -s ifconfig.me); SUBNET=$(echo $MY_IP | sed "s/\.[0-9]*$/.0\/23/"); timeout 180 /tmp/scanner --addr "$SUBNET" 2>&1 | head -80'
```

**Local mode:**
```bash
MY_IP=$(curl -4 -s ifconfig.me); SUBNET=$(echo $MY_IP | sed "s/\.[0-9]*$/.0\/23/"); timeout 180 /tmp/scanner --addr "$SUBNET" 2>&1 | head -80
```

If still nothing, use `www.yahoo.com` as a last-resort fallback -- it supports TLS 1.3 and resolves to many IPs globally, and is less commonly filtered than google/microsoft. But **always prefer a real neighbor from the scan** -- a neighbor is guaranteed to be in the same subnet and verified by the scanner for TLS 1.3 + H2 + X25519 compatibility.

Save the best SNI for the next step.

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

**22R-1: Generate guide file locally**

Use the **Write tool** to create `~/vpn-{nickname}-guide.md` on the user's local machine. Use the **Guide File Template** below, substituting all `{variables}` with actual values.

Tell user: **Методичка сохранена в ~/vpn-{nickname}-guide.md — там все пароли, доступы и инструкции.**

**22R-2: Final lockdown — fail2ban + SSH**

Verify SSH key access works:
```bash
ssh {nickname} "echo 'SSH key access OK'"
```

If successful, install fail2ban and lock SSH:
```bash
ssh {nickname} 'sudo apt install -y fail2ban && sudo tee /etc/fail2ban/jail.local << JAILEOF
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
JAILEOF
sudo systemctl enable fail2ban && sudo systemctl restart fail2ban'
```

```bash
ssh {nickname} 'sudo sed -i "s/^#\?PermitRootLogin.*/PermitRootLogin no/" /etc/ssh/sshd_config && sudo sed -i "s/^#\?PasswordAuthentication.*/PasswordAuthentication no/" /etc/ssh/sshd_config && sudo systemctl restart sshd'
```

**Verify lockdown + SSH still works:**
```bash
ssh {nickname} "grep -E 'PermitRootLogin|PasswordAuthentication' /etc/ssh/sshd_config && sudo systemctl status fail2ban --no-pager -l && echo 'Lockdown OK'"
```

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

#### 22L-6: Final lockdown — fail2ban + SSH

**Only after user confirms key-based login works!**

Install fail2ban:
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

Lock SSH:
```bash
sudo sed -i 's/^#\?PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config
sudo sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config
sudo systemctl restart sshd
```

Verify:
```bash
grep -E "PermitRootLogin|PasswordAuthentication" /etc/ssh/sshd_config
sudo systemctl status fail2ban --no-pager
```

Expected: `PermitRootLogin no`, `PasswordAuthentication no`, fail2ban active.

Tell user to verify SSH still works from laptop:
```
Проверь, что SSH-ключ всё ещё работает:
ssh {nickname}
Если подключился — всё настроено!
```

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
# Методичка VPN-сервера — {nickname}

Дата создания: {current_date}

## 1. Подключение к серверу

| Параметр | Значение |
|----------|----------|
| IP | `{SERVER_IP}` |
| Пользователь | `{username}` |
| Пароль sudo | `{sudo_password}` |
| SSH-ключ | `~/.ssh/{nickname}_key` |
| Быстрое подключение | `ssh {nickname}` |

## 2. Панель 3x-ui

| Параметр | Значение |
|----------|----------|
| URL | `https://127.0.0.1:{panel_port}/{web_base_path}` |
| Логин | `{panel_username}` |
| Пароль | `{panel_password}` |

Доступ через SSH-туннель:
```
ssh -L {panel_port}:127.0.0.1:{panel_port} {nickname}
```
Затем открой: `https://127.0.0.1:{panel_port}/{web_base_path}`

## 3. VPN-подключение

| Параметр | Значение |
|----------|----------|
| Протокол | VLESS Reality |
| Порт | 443 |
| SNI | `{best_sni}` |
| Клиент | Hiddify |

Ссылка VLESS:
```
{VLESS_LINK}
```

## 4. Настройка SSH-ключа

Если у тебя ещё нет SSH-ключа, следуй инструкциям для своей ОС:

### macOS / Linux

```bash
# Создать ключ
ssh-keygen -t ed25519 -C "{username}@{nickname}" -f ~/.ssh/{nickname}_key -N ""

# Отправить публичный ключ на сервер
scp ~/.ssh/{nickname}_key.pub {username}@{SERVER_IP}:~/

# Установить права
chmod 600 ~/.ssh/{nickname}_key

# Добавить в SSH-конфиг
cat >> ~/.ssh/config << 'SSHEOF'

Host {nickname}
    HostName {SERVER_IP}
    User {username}
    IdentityFile ~/.ssh/{nickname}_key
    IdentitiesOnly yes
SSHEOF

# Проверить подключение
ssh {nickname}
```

### Windows (PowerShell)

```powershell
# Создать ключ
ssh-keygen -t ed25519 -C "{username}@{nickname}" -f $HOME\.ssh\{nickname}_key -N '""'

# Отправить публичный ключ на сервер
scp $HOME\.ssh\{nickname}_key.pub {username}@{SERVER_IP}:~/

# Добавить в SSH-конфиг
Add-Content $HOME\.ssh\config @"

Host {nickname}
    HostName {SERVER_IP}
    User {username}
    IdentityFile ~/.ssh/{nickname}_key
    IdentitiesOnly yes
"@

# Проверить подключение
ssh {nickname}
```

Примечание: `chmod` не нужен на Windows. SSH использует ACL автоматически.

## 5. Частые команды

```bash
ssh {nickname}                           # подключиться к серверу
ssh {nickname} "sudo x-ui status"        # статус панели
ssh {nickname} "sudo x-ui restart"       # перезапустить панель
ssh {nickname} "sudo x-ui log"           # логи
ssh {nickname} "sudo x-ui setting -reset" # сбросить пароль панели
```

Добавить нового VPN-клиента:
Открой панель через SSH-туннель → Inbounds → ... → Add Client → отправь ссылку/QR.

## 6. Статус безопасности

| Параметр | Статус |
|----------|--------|
| Вход под root | Отключён |
| Вход по паролю | Отключён |
| Файрвол UFW | Включён (SSH, 80, 443) |
| fail2ban | Включён (3 попытки → бан 24ч) |
| Усиление ядра | Включено (sysctl) |
| BBR | Включён |
| ICMP (ping) | Отключён |

## 7. Решение проблем

| Проблема | Решение |
|----------|---------|
| Connection refused | `ssh {nickname} "sudo x-ui status"` — перезапусти если остановлен |
| Permission denied (publickey) | Проверь путь и права ключа: `ls -la ~/.ssh/{nickname}_key` |
| Host key verification failed | `ssh-keygen -R {SERVER_IP}` и переподключись |
| Панель недоступна | Используй SSH-туннель (см. раздел 2) |
| VPN не подключается | Неверный SNI или сервер лежит — проверь `sudo x-ui log` |
| Забыл пароль панели | `ssh {nickname} "sudo x-ui setting -reset"` |

## 8. Инструкции для Claude Code

Этот раздел для автоматической настройки через Claude Code на твоём ноутбуке.
Скопируй всё ниже и вставь в Claude Code на ноутбуке.

---

**ЗАДАЧА: Настроить SSH-ключ и завершить настройку безопасности VPN-сервера**

Данные сервера:
- SERVER_IP: {SERVER_IP}
- USERNAME: {username}
- PASSWORD: {sudo_password}
- NICKNAME: {nickname}

Шаги:

**Часть А: Установка sshpass (нужен для автоматической передачи пароля)**
1. Определи ОС и установи sshpass:
   - macOS: `brew install hudochenkov/sshpass/sshpass`
   - Linux (Debian/Ubuntu): `sudo apt install -y sshpass`

**Часть Б: Создание и установка SSH-ключа**
2. Создай SSH-ключ: `ssh-keygen -t ed25519 -C "{username}@{nickname}" -f ~/.ssh/{nickname}_key -N ""`
3. Установи ключ на сервере одной командой:
   ```
   sshpass -p '{sudo_password}' ssh-copy-id -i ~/.ssh/{nickname}_key.pub -o StrictHostKeyChecking=accept-new {username}@{SERVER_IP}
   ```
4. Проверь вход по ключу (должен работать БЕЗ пароля):
   ```
   ssh -i ~/.ssh/{nickname}_key {username}@{SERVER_IP} "echo 'SSH key OK'"
   ```
5. Добавь SSH-конфиг:
   ```
   cat >> ~/.ssh/config << 'EOF'

   Host {nickname}
       HostName {SERVER_IP}
       User {username}
       IdentityFile ~/.ssh/{nickname}_key
       IdentitiesOnly yes
   EOF
   ```
6. Проверь подключение через конфиг: `ssh {nickname} "echo 'Config OK'"`

**Часть В: Финальная защита сервера (fail2ban + блокировка пароля)**
7. Установи fail2ban:
   ```
   ssh {nickname} 'sudo apt install -y fail2ban && sudo tee /etc/fail2ban/jail.local << JAILEOF
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
   JAILEOF
   sudo systemctl enable fail2ban && sudo systemctl restart fail2ban'
   ```
8. Заблокируй парольный вход и root:
   ```
   ssh {nickname} 'sudo sed -i "s/^#\?PermitRootLogin.*/PermitRootLogin no/" /etc/ssh/sshd_config && sudo sed -i "s/^#\?PasswordAuthentication.*/PasswordAuthentication no/" /etc/ssh/sshd_config && sudo systemctl restart sshd'
   ```
9. Проверь что SSH-ключ всё ещё работает после блокировки:
   ```
   ssh {nickname} "grep -E 'PermitRootLogin|PasswordAuthentication' /etc/ssh/sshd_config && sudo systemctl status fail2ban --no-pager && echo 'Сервер полностью защищён!'"
   ```
10. Скажи пользователю: "Готово! SSH-ключ настроен, fail2ban установлен, парольный вход отключён. Подключайся: ssh {nickname}"
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
7. **All operations after Step 6 use sudo** -- not root
8. **Steps 7 and 9 are DEFERRED** -- SSH lockdown and fail2ban are installed at the very end (Step 22)

### Part 2 (VPN)
9. **NEVER expose panel to internet** -- access only via SSH tunnel
10. **NEVER skip firewall configuration** -- only open needed ports
11. **ALWAYS save panel credentials** -- show them once, clearly
12. **ALWAYS verify connection works** before declaring success
13. **Ask before every destructive or irreversible action**
14. **ALWAYS generate guide file** (Step 22) -- the user's single source of truth
15. **Lock SSH + install fail2ban LAST** (Step 22) -- only after SSH key access is verified in BOTH modes
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
