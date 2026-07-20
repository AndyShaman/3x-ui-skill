# Guide file template

At the end of setup, write a personal reference guide to the **user's own machine** (not the server) so they can reconnect, manage, and troubleshoot later. Save it somewhere the user chooses (default: the project directory or `~/`) and lock it down:

```bash
chmod 600 <path-to-guide>.md
```

## Secrets policy (reconciles the "no passwords in files" rule)

The guide must NOT contain:
- the server root password,
- the `{username}` sudo password,
- the 3x-ui panel admin password.

Those go into the user's password manager. Deliver them **once** in the chat completion summary and tell the user to store them — do not persist them to any file.

The guide MAY contain the **subscription URL**, because the user needs it to add devices and it is useless without also reaching the network. But it is sensitive (it yields full VPN configs), so the guide file is `chmod 600` and carries a visible warning. That is the deliberate exception to "no secrets in files" — a locked-down file the user owns, holding the one operational secret they can't function without, and nothing that grants server control.

## Template (fill placeholders, then save + chmod 600)

```markdown
# VPN Server — Personal Guide

> ⚠️ SENSITIVE FILE. It contains your subscription URL, which yields full VPN
> configs. Keep it private, keep permissions at 600. It does NOT contain
> server or panel passwords — those live in your password manager.

## Server
- IP: {SERVER_IP}
- SSH: `ssh {nickname}`  (key-based; root login and password auth are disabled)
- Admin user: {username}  (sudo password: in your password manager)

## VPN — how to connect (Happ)
- Install Happ ONLY from happ.su / happ.info / github.com/Happ-proxy.
- Subscription URL (⚠️ secret):
  https://{SERVER_IP}:{sub_port}/{sub_path}/{SUBID}
- Add it in Happ → Add subscription → paste.
- Android / Windows / macOS → use the "vless-xhttp-reality" (443) profile.
- iPhone / iPad → use the "vless-tcp-reality-vision" (8443) profile
  (XHTTP does not work on iOS — this is expected).
- Verify: open https://ifconfig.me — it must show {SERVER_IP}.

## Admin panel (only when you need it)
- Never exposed to the internet. Reach it via SSH tunnel:
  `ssh -L {panel_port}:127.0.0.1:{panel_port} {nickname}`
- Then open: {PANEL_SCHEME}://127.0.0.1:{panel_port}/{web_base_path}
- Username: {panel_username}   (password: in your password manager)

## Server details (for maintenance)
- Inbound 1 (primary): VLESS + XHTTP + Reality, port 443, SNI {best_sni}
- Inbound 2 (iOS/fallback): VLESS + TCP + Reality + Vision, port 8443, SNI {tcp_sni}
- Reality fingerprint: firefox  (change if firefox ever starts being flagged)
- Subscription server: port {sub_port}, path /{sub_path}/
- Firewall (UFW) open ports: {ssh_port} (SSH), 80 (cert renew), 443, 8443, {sub_port}

## Maintenance
- Panel/xray status:  `ssh {nickname} "sudo x-ui status"`
- Restart:            `ssh {nickname} "sudo x-ui restart"`
- Xray logs:          `ssh {nickname} "sudo x-ui log"`
- Update 3x-ui:       `ssh {nickname} "sudo x-ui update"`  (re-check inbounds after)
- Re-scan SNIs if a profile stops connecting: see the skill's reality-inbound reference.
- fail2ban status:    `ssh {nickname} "sudo fail2ban-client status sshd"`

## If it stops working
- One profile dead on one network → try the other profile.
- Both dead on mobile data only → your carrier likely uses IP whitelisting;
  a foreign VPS cannot bypass that by design (see the skill's whitelist notes).
- Handshake failures everywhere → your SNI was likely blacklisted; re-scan and
  update the inbound's SNI.
- Next hardening step if DPI tightens: add a Hysteria2 (UDP) inbound.
```

## Delivery, not storage

After writing the guide, the completion summary in chat should:
1. State the subscription URL once (also in the guide).
2. State the panel/sudo/server passwords once, labelled "store these in your password manager — they are NOT saved anywhere."
3. Remind the user the guide file is at `<path>` with `600` permissions.
