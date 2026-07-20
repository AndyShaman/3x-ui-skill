# Finalize: fail2ban + SSH lockdown (last step)

Run this **only at the very end**, after both inbounds work and the user has connected successfully from Happ. It disables root login and password authentication over SSH, so a mistake here locks everyone out of the server. It is deferred to the end for exactly that reason — during setup we relied on `ssh root@{SERVER_IP}`, and this step removes that path.

## The golden rule (never skip)

**Confirm key-based login actually works BEFORE disabling passwords.** The failure we are preventing: the key was never installed correctly, we disable password auth anyway, and now nobody can reach the server — not by key (broken) and not by password (disabled).

So the order is strict:
1. Prove `{username}` can log in with **only** its SSH key.
2. Write the hardening drop-in: password auth off, but root still reachable **by key** (the escape hatch).
3. Validate syntax **and** the effective merged config (`sshd -t` and `sshd -T`).
4. Restart SSH.
5. Re-verify `{username}` key login works and password login is refused — reverting through the still-working root-key path if not.
6. Only then close the root escape hatch (`PermitRootLogin no`).

Do not reorder these. Do not disable passwords "to save a step."

## Step 1: Verify key-only login for {username} (the gate)

This is the gate. It forces the key path in isolation — `BatchMode=yes` disables interactive prompts and `PasswordAuthentication=no` removes the silent fallback to password, so the command can only succeed if the key is genuinely accepted:

```bash
ssh -o BatchMode=yes -o PasswordAuthentication=no -o ConnectTimeout=10 {nickname} "echo KEY_LOGIN_OK && id && sudo -n true 2>/dev/null && echo SUDO_NOPASSWD || echo SUDO_NEEDS_PASSWORD"
```

**Decision:**
- Prints `KEY_LOGIN_OK` → key login works. **Proceed.**
- Fails / no `KEY_LOGIN_OK` → **STOP. Do NOT continue to Step 2.** The key is not accepted for `{username}`. Fix it first: confirm the public key is in `/home/{username}/.ssh/authorized_keys` on the server (check as root: `ssh root@{SERVER_IP} "cat /home/{username}/.ssh/authorized_keys"`), that `~/.ssh` is `700` and `authorized_keys` is `600` owned by `{username}`, and that your local `~/.ssh/config` entry for `{nickname}` points at the right key/user/host. Re-run this gate until it prints `KEY_LOGIN_OK`.

`SUDO_NEEDS_PASSWORD` is fine and expected — after lockdown the user types the sudo password interactively. We only needed to confirm the login channel.

## Step 2: Install and configure fail2ban

On Ubuntu 24.04 / Debian 12 the SSH auth log lives in the systemd journal, not `/var/log/auth.log`. A jail with `logpath = /var/log/auth.log` silently bans nothing. Use the systemd backend:

```bash
ssh root@{SERVER_IP} "apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y fail2ban >/dev/null 2>&1 && printf '%s\n' '[sshd]' 'enabled = true' 'backend = systemd' 'port = {ssh_port}' 'maxretry = 5' 'findtime = 600' 'bantime = 3600' > /etc/fail2ban/jail.local && systemctl enable --now fail2ban && systemctl restart fail2ban && sleep 2 && fail2ban-client status sshd"
```

`fail2ban-client status sshd` must return a jail summary (Filter/Actions). If it errors, the backend or port is wrong.

If you kept SSH on the default port, `{ssh_port}` is `22`.

## Step 3: Write the SSH hardening drop-in (00-hardening.conf)

Two facts about OpenSSH decide this step:

1. **First value wins.** `sshd_config(5)`: *"For each keyword, the first obtained value will be used."* Files in `sshd_config.d/` are read in lexical order (the `Include` sits at the top of the main config), so an **earlier** file wins, not a later one. Cloud images ship `50-cloud-init.conf` with `PasswordAuthentication yes`; a `99-` drop-in is read *after* it and is silently ignored. Name ours `00-` so it is read **first** and its values win.
2. Disable password auth now, but keep root reachable **by key** as an escape hatch (`PermitRootLogin prohibit-password`). Only after fresh `{username}` key login is re-confirmed (Step 6) do we take root away entirely (Step 7).

```bash
ssh root@{SERVER_IP} "printf '%s\n' 'PasswordAuthentication no' 'ChallengeResponseAuthentication no' 'KbdInteractiveAuthentication no' 'PubkeyAuthentication yes' 'UsePAM yes' 'PermitRootLogin prohibit-password' > /etc/ssh/sshd_config.d/00-hardening.conf && cat /etc/ssh/sshd_config.d/00-hardening.conf"
```

## Step 4: Validate syntax AND effective config before restarting

`sshd -t` checks syntax; `sshd -T` prints the **effective** config after all drop-ins merge — the only reliable proof our values actually won (a stray earlier-lexical file could still outrank us). Check both:

```bash
ssh root@{SERVER_IP} "sshd -t && echo SYNTAX_OK && sshd -T | grep -iE '^(passwordauthentication|kbdinteractiveauthentication|pubkeyauthentication|permitrootlogin) '"
```

Must print `SYNTAX_OK`, then exactly:

```
passwordauthentication no
kbdinteractiveauthentication no
pubkeyauthentication yes
permitrootlogin prohibit-password
```

If `passwordauthentication` is still `yes`, another drop-in outranks ours — **STOP**. Find it (`ssh root@{SERVER_IP} "grep -rn PasswordAuthentication /etc/ssh/sshd_config /etc/ssh/sshd_config.d/"`) and either rename ours to sort before it or neutralize the conflicting line. Do not restart until the effective config reads as above.

## Step 5: Restart SSH

The service is `ssh` on Debian/Ubuntu and `sshd` on RHEL-family. Try both:

```bash
ssh root@{SERVER_IP} "systemctl restart ssh 2>/dev/null || systemctl restart sshd"
```

Root is still reachable **by key** (`prohibit-password`) — the deliberate escape hatch, kept open until Step 6 confirms `{username}` works and Step 7 closes it.

## Step 6: Verify the new state (both directions)

Fresh key login as `{username}` must still work, and password auth must now be refused:

```bash
ssh -o BatchMode=yes -o PasswordAuthentication=no -o ConnectTimeout=10 {nickname} "echo STILL_IN && id"
ssh -o BatchMode=yes -o PubkeyAuthentication=no -o PreferredAuthentications=password -o ConnectTimeout=10 {username}@{SERVER_IP} "echo SHOULD_NOT_HAPPEN" 2>&1 | grep -q "Permission denied\|no supported authentication" && echo "PASSWORD_AUTH_DISABLED_OK" || echo "WARNING: password auth still reachable"
```

Expect `STILL_IN` and `PASSWORD_AUTH_DISABLED_OK`.

**If `STILL_IN` does not print** — `{username}` key login is broken. Root is still reachable by key right now, so revert immediately through a **fresh root-key session** (this works precisely because Step 3 kept `prohibit-password`):

```bash
ssh root@{SERVER_IP} "rm -f /etc/ssh/sshd_config.d/00-hardening.conf && (systemctl restart ssh 2>/dev/null || systemctl restart sshd) && echo REVERTED"
```

Then fix the key (Step 1 diagnostics) and retry from Step 3. Do **not** proceed to Step 7 until both lines above pass.

## Step 7: Close the root escape hatch

Only now that fresh `{username}` key login is confirmed, take root away. Flip the one directive, re-validate the effective config, restart, then confirm root is refused **and** `{username}` still works:

```bash
ssh root@{SERVER_IP} "sed -i 's/^PermitRootLogin .*/PermitRootLogin no/' /etc/ssh/sshd_config.d/00-hardening.conf && sshd -t && sshd -T | grep -i '^permitrootlogin ' && (systemctl restart ssh 2>/dev/null || systemctl restart sshd)"
ssh -o BatchMode=yes -o ConnectTimeout=10 root@{SERVER_IP} "echo ROOT_STILL_IN" 2>&1 | grep -q "Permission denied\|no supported authentication" && echo "ROOT_LOGIN_DISABLED_OK" || echo "WARNING: root login still reachable"
ssh -o BatchMode=yes -o PasswordAuthentication=no -o ConnectTimeout=10 {nickname} "echo FINAL_OK && id"
```

Expect `permitrootlogin no` in the effective config, `ROOT_LOGIN_DISABLED_OK`, and `FINAL_OK`. Because Step 6 already proved the `{username}` key path and only `PermitRootLogin` changed here, the final `{nickname}` check will pass. If it somehow failed, root is already gone — recover via the provider console (below). Alternatively, if flipping root breaks something, revert via the user's own sudo path (still works post-lockdown):

```bash
ssh {nickname} "sudo sed -i 's/^PermitRootLogin .*/PermitRootLogin prohibit-password/' /etc/ssh/sshd_config.d/00-hardening.conf && sudo systemctl restart ssh"
```

From here on, connect only as `{nickname}` and use `sudo` interactively.

## Step 8 (optional): confirm BBR is active

If BBR was enabled earlier in setup, confirm it survived:

```bash
ssh {nickname} "sysctl net.ipv4.tcp_congestion_control | grep -q bbr && echo BBR_ON || echo BBR_OFF"
```

## What changed / lockout recovery

After this step: root SSH login disabled, password SSH auth disabled, fail2ban banning brute-force on `{ssh_port}`, access only as `{username}` via key.

If you ever do lock yourself out despite the gate (e.g. the key file is later deleted locally), recover through the VPS provider's **web console / VNC / recovery mode** — that path bypasses sshd entirely. Log in as root there, then either re-add your key to `/home/{username}/.ssh/authorized_keys` or temporarily `rm /etc/ssh/sshd_config.d/00-hardening.conf` and restart ssh.
