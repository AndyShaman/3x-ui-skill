---
name: 3x-ui-setup
description: Complete VPN server setup from scratch — takes a fresh VPS (IP + root password from the hosting provider) through full server hardening and a 3x-ui (Xray) install with two VLESS+Reality inbounds (XHTTP for best DPI resistance, TCP+Vision for iOS), delivered as one subscription link and connected via the Happ client. Tuned for Russian users facing 2026 DPI. Use when the user mentions v2ray, xray, vless, reality, 3x-ui, proxy server, vpn server, or wants encrypted proxy access on a VPS. Hand-holds beginners through every step.
allowed-tools: Bash,Read,Write,Edit
---

# VPN Server Setup (3x-ui)

Fresh VPS from a provider → hardened server → working VPN (two VLESS+Reality profiles in one subscription) → Happ client. Built and tuned for the RU 2026 DPI landscape.

## What this builds

- **Primary inbound:** VLESS + **XHTTP** + Reality on port 443 — best DPI resistance (hides both the TLS handshake and post-handshake behaviour).
- **Fallback inbound:** VLESS + **TCP** + Reality + **Vision** + padding on port 8443 — required for iOS (XHTTP+Reality is broken on Happ iOS) and adds detection diversity.
- **One subscription link** serving both, imported once into **Happ**.
- Server hardened: non-root user, key-only SSH, UFW, kernel sysctl, fail2ban, BBR, no ICMP.

Read `references/whitelist-and-fallbacks.md` early to set honest expectations — on mobile networks in whitelist regions a foreign VPS cannot help, and that must be communicated up front.

## Reference map (progressive disclosure)

| File | When |
|------|------|
| `references/reality-inbound.md` | Part 2 — create both Reality inbounds |
| `references/subscription.md` | Part 2 — subscription server + LE cert on IP + panel tunnel |
| `references/client-happ.md` | Part 2 — install Happ, import, connect, troubleshoot |
| `references/finalize-hardening.md` | Final step — fail2ban + SSH lockdown (key-verify gate) |
| `references/guide-template.md` | Final step — the personal guide file + secrets policy |
| `references/whitelist-and-fallbacks.md` | Expectations + fallback ladder + SNI pool + Hysteria2 next step |
| `references/local-mode.md` | If Claude Code runs ON the VPS |
| `references/vless-tls.md` | Optional: domain-based VLESS+TLS instead of Reality |
| `references/fallback-nginx.md` | Optional: benign stub site behind VLESS+TLS |

## Workflow overview

```
PART 1 — Server hardening
  Fresh VPS (IP + root password)
    → mode (remote/local) → SSH key → connect as root → update
    → create non-root user + sudo → install key (user AND root)
    → TEST key login (critical) → UFW → kernel sysctl → packages
    → local ~/.ssh/config → ✅ server secured
PART 2 — VPN
    → install 3x-ui → detect panel scheme → BBR → disable ICMP
    → two Reality inbounds (reality-inbound.md)
    → subscription + cert (subscription.md)
    → Happ (client-happ.md) → verify
    → guide file (guide-template.md)
    → fail2ban + SSH lockdown LAST, after key verified (finalize-hardening.md)
    → ✅ VPN working
```

---

# PART 1: Server Hardening

## Step 0: Collect information & pick mode

**Where is Claude Code running?**
- **Local computer** → Remote mode (configure a remote VPS over SSH). Default; this file is written for it.
- **On the VPS itself** → Local mode. Follow `references/local-mode.md` for the deltas (drop the SSH wrapper; the lockdown gate becomes a human handshake).

**Remote mode — ask for:** server IP, root password (both from the provider email), desired non-root username, a server nickname for SSH config, whether they have a domain (recommend "no" → Reality). If they paste the whole provider email, extract the values.

**Local mode — ask for:** username, nickname, domain (recommend "no"). Get the IP automatically: `curl -4 -s ifconfig.me`.

**Recommend Reality (no domain)** for beginners: works without a domain, free, better DPI resistance. TLS needs a domain (~$10/yr) — only if the user specifically wants a fallback site.

**SSH port:** set `{ssh_port}` = `22` now, as an explicit default. Only override if the user says they run SSH on a non-standard port. This value is substituted verbatim into UFW (Step 8) and fail2ban (finalize) — leaving it blank breaks both, so never treat it as an unfilled placeholder.

## Step 1: Generate SSH key (LOCAL machine)

```bash
ssh-keygen -t ed25519 -C "{username}@{nickname}" -f ~/.ssh/{nickname}_key -N ""
cat ~/.ssh/{nickname}_key.pub   # save this — {PUBLIC_KEY_CONTENT}
```

## Step 2: First connection as root

```bash
ssh root@{SERVER_IP}
```

Many providers force a password change on first login ("password expired" / "change immediately"): enter the provider password, then a strong temporary one. If the connection drops afterwards, that's normal — reconnect.

## Step 3: System update (as root)

```bash
apt update && DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=a apt upgrade -y
```

## Step 4: Create non-root user

```bash
useradd -m -s /bin/bash {username}
echo "{username}:{sudo_password}" | chpasswd
usermod -aG sudo {username}
groups {username}
```

Generate a strong random password. Tell the user to store it in their password manager (needed for sudo) — do **not** write it to any file.

## Step 5: Install SSH key (new user AND root)

Install for the new user:

```bash
mkdir -p /home/{username}/.ssh
echo "{PUBLIC_KEY_CONTENT}" > /home/{username}/.ssh/authorized_keys
chmod 700 /home/{username}/.ssh && chmod 600 /home/{username}/.ssh/authorized_keys
chown -R {username}:{username} /home/{username}/.ssh
```

Also install it for **root** — this lets Part 2 run as root over SSH **key-based and non-interactive** (no hanging sudo prompt), until the final step disables root login entirely:

```bash
mkdir -p /root/.ssh
echo "{PUBLIC_KEY_CONTENT}" >> /root/.ssh/authorized_keys
chmod 700 /root/.ssh && chmod 600 /root/.ssh/authorized_keys
```

## Step 6: TEST key login — CRITICAL CHECKPOINT

**Do not proceed without a successful test.** Test non-interactively — `sudo whoami` would prompt for a password and hang, so verify with `id` instead (group membership proves sudo access without needing the password):

```bash
ssh -i ~/.ssh/{nickname}_key -o BatchMode=yes -o PasswordAuthentication=no -o ConnectTimeout=10 {username}@{SERVER_IP} "id"
```

Success = prints an `id` line listing the `sudo` group. That confirms both key login and sudo membership. **If it fails**, fix permissions from the still-open root session (do NOT disable root):

```bash
ls -la /home/{username}/.ssh/ && cat /home/{username}/.ssh/authorized_keys
chown -R {username}:{username} /home/{username}/.ssh
```

## Step 7: SSH lockdown — DEFERRED

**Both modes: skip for now.** Disabling root login and password auth happens **last** (`references/finalize-hardening.md`), only after key access is verified end-to-end. Deferring it prevents locking yourself out mid-setup. This is why Part 2 runs as root — the root escape hatch stays open until the very end.

## Step 8: Firewall (UFW)

```bash
apt install -y ufw
ufw default deny incoming && ufw default allow outgoing
ufw allow {ssh_port}/tcp
ufw allow 80/tcp && ufw allow 443/tcp && ufw allow 8443/tcp
ufw --force enable && ufw status
```

`{ssh_port}` is `22` unless changed. Ports 443 (XHTTP) and 8443 (TCP+Vision) are for the two inbounds; 80 is for the LE cert challenge. The subscription port is opened later in `subscription.md`. The panel port is deliberately **never** opened.

## Step 9: fail2ban — DEFERRED

Installed at the end alongside the SSH lockdown (`references/finalize-hardening.md`), with `backend=systemd` (journald), so it doesn't ban you mid-setup.

## Step 10: Kernel hardening

```bash
tee /etc/sysctl.d/99-security.conf << 'EOF'
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
sysctl -p /etc/sysctl.d/99-security.conf
```

## Step 11: Time sync + base packages

```bash
apt install -y chrony curl wget unzip net-tools sqlite3 openssl
systemctl enable chrony
```

## Step 12: Configure local SSH config

On the user's LOCAL machine. The second block lets `ssh root@{SERVER_IP}` use the key during Part 2:

```bash
grep -q "^Host {nickname}$" ~/.ssh/config 2>/dev/null || cat >> ~/.ssh/config << 'EOF'

Host {nickname}
    HostName {SERVER_IP}
    User {username}
    IdentityFile ~/.ssh/{nickname}_key
    IdentitiesOnly yes

Host {SERVER_IP}
    IdentityFile ~/.ssh/{nickname}_key
    IdentitiesOnly yes
EOF
```

The `grep` guard keeps a re-run from appending a duplicate `Host` block.

Tell the user: **теперь подключайся командой `ssh {nickname}` — без пароля и IP.**

## Step 13: Final verification (Part 1)

```bash
ssh {nickname} "sudo -n true 2>/dev/null; sudo ufw status; sysctl net.ipv4.conf.all.rp_filter"
```

Expected: UFW active, `rp_filter = 1`. SSH lockdown + fail2ban are verified at the very end.

**Part 1 done. Server is hardened. On to the VPN.**

---

# PART 2: VPN Installation (3x-ui)

Part 2 runs as **root over SSH key** (`ssh root@{SERVER_IP}`) — root stays reachable until the final lockdown, and this avoids non-interactive sudo prompts. (Local mode: drop the wrapper — see `references/local-mode.md`.)

## Step 14: Install 3x-ui

```bash
ssh root@{SERVER_IP} "curl -Ls https://raw.githubusercontent.com/mhsanaei/3x-ui/master/install.sh -o /tmp/3x-ui-install.sh && echo 'n' | bash /tmp/3x-ui-install.sh"
```

`echo 'n'` declines the port-customization prompt (a random port + credentials are generated). Do **not** use `bash <(curl ...)` — process substitution breaks under this pattern.

**Capture the output** — it contains the generated panel username, password, port, and web base path. Show them to the user to store (do not save to a file):

```
Данные панели 3x-ui (сохрани в менеджер паролей):
  Username: {panel_username}   Password: {panel_password}
  Port: {panel_port}   Path: {web_base_path}
```

The installer also writes these same credentials to `/etc/x-ui/install-result.env` (mode 0600) — but the console output above is our source of truth, and our rule is that panel passwords live in no file. Once the user has saved them, delete it:

```bash
ssh root@{SERVER_IP} "rm -f /etc/x-ui/install-result.env && test ! -f /etc/x-ui/install-result.env && echo CREDS_FILE_REMOVED"
```

Verify: `ssh root@{SERVER_IP} "x-ui status"` (start with `x-ui start` if needed). The panel port is **not** opened in UFW — access is via SSH tunnel only.

**Detect the panel scheme** (3x-ui may serve HTTP or HTTPS — guessing wrong makes every API call fail). Save the result as `{PANEL_SCHEME}`, used by the reference files:

```bash
ssh root@{SERVER_IP} 'P={panel_port}; curl -sk --max-time 5 "https://127.0.0.1:$P/{web_base_path}/" -o /dev/null 2>/dev/null && echo https || echo http'
```

## Step 15: Enable BBR

BBR sharply improves TCP throughput on lossy links. Idempotent (the guard prevents duplicate lines on re-run):

```bash
ssh root@{SERVER_IP} 'c=$(sysctl -n net.ipv4.tcp_congestion_control); if [ "$c" != "bbr" ]; then grep -q "^net.core.default_qdisc=fq" /etc/sysctl.conf || echo "net.core.default_qdisc=fq" >> /etc/sysctl.conf; grep -q "^net.ipv4.tcp_congestion_control=bbr" /etc/sysctl.conf || echo "net.ipv4.tcp_congestion_control=bbr" >> /etc/sysctl.conf; sysctl -p; fi; sysctl net.ipv4.tcp_congestion_control'
```

Expected: `net.ipv4.tcp_congestion_control = bbr`.

## Step 16: Disable ICMP (stealth)

```bash
ssh root@{SERVER_IP} "sed -i 's/-A ufw-before-input -p icmp --icmp-type echo-request -j ACCEPT/-A ufw-before-input -p icmp --icmp-type echo-request -j DROP/' /etc/ufw/before.rules && sed -i 's/-A ufw-before-forward -p icmp --icmp-type echo-request -j ACCEPT/-A ufw-before-forward -p icmp --icmp-type echo-request -j DROP/' /etc/ufw/before.rules && sed -i 's/-A ufw6-before-input -p ipv6-icmp --icmp-type echo-request -j ACCEPT/-A ufw6-before-input -p ipv6-icmp --icmp-type echo-request -j DROP/' /etc/ufw/before6.rules 2>/dev/null; ufw reload"
```

The third `sed` drops IPv6 echo (`ping6`) too, so a dual-stack VPS goes fully dark; it touches only `echo-request`, leaving IPv6 neighbour discovery intact, and `2>/dev/null; ` makes it a no-op on IPv6-disabled hosts. Verify from local: `ping -c 2 -W 2 {SERVER_IP}` should time out (and `ping6 {SERVER_IP}` if the VPS has IPv6).

## Step 17: Create the two Reality inbounds

Follow **`references/reality-inbound.md`** end to end. It covers: port pre-checks, key/UUID/subId generation (note: `xray x25519` now prints **three** lines; the Reality public key is the `Password` value), the SNI scanner over the /24 subnet (pick two SNIs — one per inbound), and the exact API bodies for:
- the **XHTTP+Reality** primary on 443 (`mode=stream-one`, empty flow, `fingerprint=firefox`), and
- the hardened **TCP+Reality+Vision** fallback on 8443 (`flow=xtls-rprx-vision`, `fingerprint=firefox`, padding).

Both clients share one `{SUBID}` so a single subscription returns both.

## Step 18: Subscription server + certificate

Follow **`references/subscription.md`**: keep the panel bound to loopback, issue a Let's Encrypt certificate for the bare IP (non-interactive acme.sh; x-ui menu / DuckDNS are fallbacks), enable the subscription on a random port + random path over HTTPS, open the subscription port in UFW, and build the subscription URL `https://{SERVER_IP}:{sub_port}/{sub_path}/{SUBID}`. Verify it returns both profiles before handing it over.

## Step 19: Install & connect Happ

Follow **`references/client-happ.md`**: install Happ **only** from official sources (happ.su / happ.info / github.com/Happ-proxy — warn about scam clones), import the subscription, and pick the profile (XHTTP/443 on Android/desktop; TCP/8443 on iOS, since XHTTP+Reality is broken on Happ iOS).

## Step 20: Verify connection

After the user connects, confirm both inbounds are bound and traffic exits the server:

```bash
ssh root@{SERVER_IP} "x-ui status && ss -tlnp | grep -E ':(443|8443) '"
```

Have the user open `https://ifconfig.me` — it must show `{SERVER_IP}`. If a profile fails, use the fallback ladder in `references/whitelist-and-fallbacks.md`.

## Step 21: Generate the guide file

Follow **`references/guide-template.md`**: write a personal guide to the **user's** machine, `chmod 600`. It holds operational details and the subscription URL (sensitive), but **never** server/sudo/panel passwords — those are delivered once in chat for the password manager.

## Step 22: Finalize — fail2ban + SSH lockdown (LAST)

**Only now**, after both profiles work. Follow **`references/finalize-hardening.md`**. The golden rule, per the user's requirement: **confirm key-based login actually works before disabling password auth**, using an isolated key-only test (`ssh -o BatchMode=yes -o PasswordAuthentication=no ...`) so you never end up locked out with passwords already off. The reference also validates the config offline (`sshd -t`) before restarting and re-verifies both directions afterwards, and installs fail2ban with `backend=systemd` (M-series fixes for Ubuntu 24.04 / Debian 12).

After this step, root login and password auth are disabled; from here on connect only as `ssh {nickname}` and use `sudo` interactively.

---

## Completion summary

Print for the user (deliver passwords here, once — they are stored nowhere):

```
VPN-сервер настроен и работает.

Сервер:
   ssh {nickname}   (вход только по ключу; root и пароль отключены)
   IP: {SERVER_IP}   Пользователь: {username}
   Пароль sudo: {sudo_password}   ← сохрани в менеджер паролей, нигде не записан

Панель 3x-ui (только через SSH-туннель):
   ssh -L {panel_port}:127.0.0.1:{panel_port} {nickname}
   {PANEL_SCHEME}://127.0.0.1:{panel_port}/{web_base_path}
   Login: {panel_username}   Password: {panel_password}  ← в менеджер паролей

VPN — подписка (одна ссылка, оба профиля):
   https://{SERVER_IP}:{sub_port}/{sub_path}/{SUBID}   ← секрет, храни как пароль
   Android/Windows/macOS → профиль XHTTP (443)
   iPhone/iPad → профиль TCP/Vision (8443)
   Клиент: Happ (только happ.su / happ.info / github.com/Happ-proxy)

Безопасность: UFW (SSH, 80, 443, 8443, {sub_port}), fail2ban (systemd),
   ядро усилено, BBR включён, ICMP отключён.

Методичка: {guide_path}  (chmod 600 — в ней и подписка)
Ожидания и обход блокировок: см. references/whitelist-and-fallbacks.md
```

## Critical rules

**Server (Part 1 + finalize)**
1. Never skip Step 6 (key-login test) — a bad key means a locked-out server.
2. Never disable root or password auth before confirming key login works — this is the user's explicit requirement, enforced by the gate in `finalize-hardening.md`.
3. Never store server, sudo, or panel **passwords** in any file — display once for the password manager. The subscription URL is the one allowed exception, and only inside the `chmod 600` guide file with a visible warning (see `guide-template.md`).
4. Validate `sshd -t` before restarting sshd, and keep the current session open until the new state is verified.
5. Lock SSH + install fail2ban **last**, in both modes.

**VPN (Part 2)**
6. Never expose the panel to the internet — SSH tunnel only, panel bound to `127.0.0.1`.
7. Open only the needed UFW ports; never open the panel port.
8. Keep secrets out of shell history/process list where practical (loopback-only curl, stdin for passwords). On a single-tenant VPS the brief `ps` exposure is acceptable.
9. Verify the connection works before declaring success.
10. Ask before any destructive or irreversible action.

## Troubleshooting (spine)

| Problem | Solution |
|---------|----------|
| Non-interactive `sudo` hangs in Part 2 | Run as root: `ssh root@{SERVER_IP}` (root key installed in Step 5) |
| API calls fail with TLS errors | Wrong scheme — re-run the Step 14 scheme detection, use `{PANEL_SCHEME}` |
| `Permission denied (publickey)` | Check key path + perms (700/600); confirm Step 5 installed the key |
| `Host key verification failed` | `ssh-keygen -R {SERVER_IP}` then reconnect |
| x-ui install fails | `ssh root@{SERVER_IP} "apt update && apt install -y curl tar"` then retry |
| Inbound won't bind :443/:8443 | Port occupied (apache2/nginx) or bad SNI dest — see `reality-inbound.md` |
| iOS connects, no internet | Use the TCP/8443 profile, not XHTTP — see `client-happ.md` |
| Works on Wi-Fi, dead on mobile data | Whitelist region — a foreign VPS can't help; see `whitelist-and-fallbacks.md` |
| Forgot panel password | `ssh {nickname} "sudo x-ui setting -reset"` |

## x-ui CLI reference

```bash
x-ui start | stop | restart | status
x-ui setting -reset   # reset panel username/password
x-ui log              # view logs
x-ui cert             # manage SSL certificates
x-ui update           # update to latest version
```
