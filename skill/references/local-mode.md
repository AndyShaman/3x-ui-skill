# Local mode (Claude Code running ON the VPS)

Use this when the skill runs from a shell **on the server itself** (the user SSH'd in and started Claude Code there), not from a laptop driving a remote box. Everything in the other references still applies — only the execution wrapper and the SSH-lockdown safety gate change.

## Delta 1: drop the SSH wrapper

Every command written as `ssh root@{SERVER_IP} "..."` or `ssh {nickname} "..."` in the other references runs **locally** here. Strip the wrapper and run the inner command directly.

Run as **root** for the setup phase (panel API, xray binary, x25519). If Claude Code was started under a sudo-capable user, either:
- start it as root, or
- have the user grant temporary passwordless sudo for the session and prefix commands with `sudo`, removing it at the end.

Non-interactive `sudo` that prompts for a password will hang — Claude cannot type it. Confirm up front which case applies:

```bash
id -u   # 0 = root, good. Otherwise check: sudo -n true && echo NOPASSWD || echo NEEDS_PASSWORD
```

## Delta 2: panel access is still loopback

The panel binds `127.0.0.1` regardless of mode. To reach the UI, the **user** opens a tunnel *from their own machine* to the server:

```bash
# run on the user's laptop, not here
ssh -L {panel_port}:127.0.0.1:{panel_port} {username}@{SERVER_IP}
```

You cannot open a browser from inside the VPS; hand the tunnel command to the user for any UI step (subscription settings, 2FA).

## Delta 3: the SSH-lockdown safety gate becomes a human handshake

In remote mode the gate is `ssh -o BatchMode=yes -o PasswordAuthentication=no {nickname} ...` — you test key login from the outside. **On the server you cannot test your own inbound SSH from outside.** So the gate is delegated to the user, and this is where a lockout would happen if skipped.

Before writing `00-hardening.conf` (see `finalize-hardening.md` Step 3), do this handshake:

1. Ask the user to open a **new, second** SSH session from their laptop, using the key, and keep it open:
   ```bash
   ssh -o BatchMode=yes -o PasswordAuthentication=no {username}@{SERVER_IP} "echo KEY_LOGIN_OK && id"
   ```
2. The user pastes back the output. It must contain `KEY_LOGIN_OK`.
3. Only after the user confirms that second session is **alive and key-based**, apply the lockdown config and validate with `sshd -t`.
4. Restart SSH. The user's second session (and your current one) survive the restart — they are the escape hatch.
5. Ask the user to open a **third** fresh session to confirm the locked-down state still admits the key. If it fails, revert immediately from the still-open second session:
   ```bash
   sudo rm -f /etc/ssh/sshd_config.d/00-hardening.conf && (sudo systemctl restart ssh 2>/dev/null || sudo systemctl restart sshd)
   ```

Do not apply the lockdown on your say-so alone in local mode — you have no way to independently verify inbound key auth, so the user's confirmed second session is the safety net.

## Everything else

SNI scanning, inbound creation, subscription config, fail2ban (`backend=systemd`), the Happ client section — all identical to the remote references, just without the SSH wrapper. Follow them in the same order.
