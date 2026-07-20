# Subscription server (public) + panel over SSH tunnel

The user chose subscription-link delivery: one URL that returns **both** the XHTTP and TCP profiles, so a single import in Happ gives the client both and it picks whichever connects. When you rotate SNIs or add a client later, the phone re-fetches and updates itself — no re-scanning QR codes.

Two listeners, two very different exposure levels:

| Listener | Bind | Exposure | Why |
|----------|------|----------|-----|
| **Panel** (`{web_base_path}`) | `127.0.0.1` only | Never public — reached via SSH tunnel | The admin panel is the crown jewel; exposing it invites brute-force and 0-days |
| **Subscription** | all interfaces, random port `{sub_port}` | Public over HTTPS at a random path | The phone must fetch it over the internet |

The subscription content lists your UUIDs, SNIs and keys — anyone who reads it can connect to or fingerprint your server. So it must be HTTPS (not plain HTTP) and live at an unguessable path.

## Step 1: Confirm the panel binds to loopback only

```bash
ssh root@{SERVER_IP} "x-ui setting -show 2>/dev/null | grep -iE 'listen' || true; ss -tlnp | grep {panel_port}"
```

If the panel listens on `0.0.0.0:{panel_port}` instead of `127.0.0.1`, close it (the flag is `-listenIP`, not `-webListen`):

```bash
ssh root@{SERVER_IP} "x-ui setting -listenIP 127.0.0.1 && x-ui restart && sleep 1 && ss -tlnp | grep {panel_port}"
```

The follow-up `ss` must show the panel bound to `127.0.0.1:{panel_port}` (or `[::1]`) only — if it still shows `0.0.0.0`, **STOP** and fix before continuing. UFW must **not** have a rule opening `{panel_port}`. The only way in is the tunnel (Step 5).

## Step 2: Get a Let's Encrypt certificate for the bare IP

No domain is required — Let's Encrypt issues short-lived certificates for bare IPs (GA since 2026-01-15) via the `shortlived` profile (~6 days, auto-renewed by acme.sh's own cron). Issue it **non-interactively** with acme.sh — the exact commands 3x-ui's menu runs internally, so the result is identical but scriptable. Port 80 must be free for the HTTP-01 challenge (nothing binds it; UFW opened it in Part 1). First prepare acme.sh:

```bash
ssh root@{SERVER_IP} "command -v ~/.acme.sh/acme.sh >/dev/null 2>&1 || curl -fsSL https://get.acme.sh | sh >/dev/null 2>&1; DEBIAN_FRONTEND=noninteractive apt-get install -y socat >/dev/null 2>&1; mkdir -p /root/cert/ip; ~/.acme.sh/acme.sh --set-default-ca --server letsencrypt --force >/dev/null 2>&1 && echo ACME_READY"
```

Then issue and install the cert into `/root/cert/ip/`, with a reload hook so every automatic renewal restarts x-ui:

```bash
ssh root@{SERVER_IP} "~/.acme.sh/acme.sh --issue -d {SERVER_IP} --standalone --server letsencrypt --certificate-profile shortlived --days 6 --httpport 80 && ~/.acme.sh/acme.sh --installcert --force -d {SERVER_IP} --key-file /root/cert/ip/privkey.pem --fullchain-file /root/cert/ip/fullchain.pem --reloadcmd 'x-ui restart'; test -s /root/cert/ip/fullchain.pem && test -s /root/cert/ip/privkey.pem && echo CERT_OK || echo CERT_FAIL"
```

Must print `CERT_OK`. The files land in `/root/cert/ip/` as `fullchain.pem` / `privkey.pem`. Renewal is automatic — acme.sh's cron re-issues before the 6-day expiry and runs the reload hook; do **not** add a second renewal timer.

**Fallbacks, in order, if IP issuance fails** (some providers/regions block port 80 or IP certs):
1. **Interactive x-ui menu** — hand this to the user to run in their own terminal (it needs a TTY, so an automated tool call cannot drive it): `ssh -t root@{SERVER_IP} "x-ui"` → **SSL Certificate Management → Get SSL Certificate for IP Address**. It writes the same `/root/cert/ip/` files.
2. **Free dynamic domain (DuckDNS)** pointed at the IP, then `references/vless-tls.md` Step 2's acme flow for that domain — a normal 90-day cert with no weekly renewal window, so it is the more robust option where IP certs are blocked.
3. Last resort — plain HTTP leaks every config to any on-path observer; if unavoidable, keep the random path and warn the user their configs are exposed in transit.

## Step 3: Configure the subscription server (panel Settings)

Subscription settings are not exposed by the `x-ui` CLI, and the setting API path moved under `/panel/api/` in v3.3.0 — versions differ. The version-agnostic path is the panel UI over the tunnel. Open the tunnel (Step 5), then in **Panel → Settings → Subscription** set:

| Field | Value | Note |
|-------|-------|------|
| Enable | on | |
| Listen IP | empty | all interfaces, so the phone can reach it |
| Port | `{sub_port}` | random high port, e.g. `2087` — pick one that isn't 443/8443/{panel_port} |
| Path | `/{sub_path}/` | random, leading+trailing slash, e.g. `/s7k2p9x1a/` |
| Public URL / Domain | `https://{SERVER_IP}:{sub_port}` | must be HTTPS |
| Certificate file | `/root/cert/ip/fullchain.pem` | from Step 2 |
| Key file | `/root/cert/ip/privkey.pem` | |
| Enable JSON (`subJsonPath`) | on | Happ prefers the JSON subscription; keep the base64 one on too |

Save, then restart:

```bash
ssh root@{SERVER_IP} "x-ui restart"
```

**Fallback if the UI is unreachable:** stop the panel and edit the settings table directly, then restart (adjust field names to your version — `subEnable`, `subPort`, `subPath`, `subURI`, `subCertFile`, `subKeyFile`, `subJsonPath`):

```bash
ssh root@{SERVER_IP} "x-ui stop; sqlite3 /etc/x-ui/x-ui.db \"UPDATE settings SET value='true' WHERE key='subEnable';\"; x-ui start"
```

Prefer the UI — direct DB edits vary by schema version and can corrupt settings.

## Step 4: Open the subscription port in the firewall

```bash
ssh root@{SERVER_IP} "ufw allow {sub_port}/tcp && ufw reload && ufw status numbered"
```

UFW should now allow: `{ssh_port}` (SSH), 80 (ACME), 443 (XHTTP), 8443 (TCP), `{sub_port}` (subscription). It must **not** list `{panel_port}`.

## Step 5: SSH tunnel to the panel (admin only)

For any panel UI work, tunnel loopback to your machine — never open the panel port publicly:

```bash
ssh -L {panel_port}:127.0.0.1:{panel_port} {nickname}
```

Then browse `{PANEL_SCHEME}://127.0.0.1:{panel_port}/{web_base_path}`. The browser will warn about the self-signed/IP certificate on the panel — that is expected over the tunnel; accept it. Close the tunnel when done.

## Step 6: Build and verify the subscription URL

The URL is `https://{SERVER_IP}:{sub_port}/{sub_path}/{SUBID}`. Verify it returns content (base64 of the two vless links) before handing it to the user:

```bash
curl --fail --show-error --max-time 10 -s "https://{SERVER_IP}:{sub_port}/{sub_path}/{SUBID}" | head -c 200; echo
```

A non-empty base64 blob = working. `--fail` makes curl exit non-zero on an HTTP error and `--show-error` surfaces a TLS failure instead of printing empty output — so an expired/mismatched cert (which Happ would also reject) reads as a real error, not a silent blank. Decode to sanity-check both profiles are present:

```bash
curl --fail --show-error --max-time 10 -s "https://{SERVER_IP}:{sub_port}/{sub_path}/{SUBID}" | base64 -d
```

You should see two `vless://` lines — one `type=xhttp` (443) and one `type=tcp&flow=xtls-rprx-vision` (8443). If only one appears, the two clients don't share `{SUBID}` — fix the `subId` on the missing inbound's client.

The JSON subscription (for Happ) is the same URL with the JSON path if you set `subJsonPath` separately; the panel shows the exact "Subscription URL" and "Subscription JSON URL" on each client's row.

## What to hand the user

Give them the subscription URL only — not the raw vless links. Store it per the guide template (`references/guide-template.md`), which handles secrets carefully. The subscription URL itself is sensitive (it yields full configs); treat it like a password.
