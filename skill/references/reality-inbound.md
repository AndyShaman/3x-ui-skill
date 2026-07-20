# VLESS Reality Inbounds (XHTTP primary + hardened TCP fallback)

Creates **two** VLESS+Reality inbounds and one subscription that serves both:

| Inbound | Transport | Port | Purpose |
|---------|-----------|------|---------|
| Primary | **XHTTP** (`mode=stream-one`) + Reality | 443 | Best DPI resistance in RU 2026 (defeats behavioural analysis) |
| Fallback | **TCP** + Reality + **Vision** + padding | 8443 | **Required for iOS** (XHTTP+Reality is broken on Happ iOS) + DPI diversity |

Both clients share ONE `subId`, so a single subscription link returns both profiles and the client picks whichever connects. See `subscription.md` for the link itself.

## Why two inbounds, this exact way

- **XHTTP+Reality is the 2026 default** — Reality hides the TLS handshake, XHTTP hides post-handshake *behaviour* (packet timing/sizes). They cover different DPI layers. The May-2026 TSPU signature that kills naive TCP-Reality is a behavioural one; XHTTP sidesteps it.
- **iOS cannot use XHTTP+Reality at all** — on Happ/iOS the Reality handshake completes but no HTTP data flows (`firstLen=0`, EOF) across every `mode` (Xray-core discussion #5918). So iPhone/iPad users need the plain TCP+Reality+Vision profile. This is the primary reason the TCP inbound exists; DPI diversity is a bonus.
- **`flow` is empty on XHTTP, `xtls-rprx-vision` only on TCP** — Vision is incompatible with XHTTP (Xray returns error -1; 3x-ui issue #4897). Putting a flow on the XHTTP inbound is the #1 misconfiguration.
- **`mode=stream-one` must be set explicitly** — `auto` has confirmed bugs: Xray-core #5635 (auto+Reality version mismatch) and Hiddify/sing-box #2082 (auto silently falls back to `packet-up`, breaking Telegram uploads). Set it on the server AND in the link.
- **Reality is incompatible with any CDN** — it is point-to-point (client ↔ your VPS). Never front it with Cloudflare.
- **`fingerprint=firefox`, not chrome** — the June-2026 TSPU wave flags `chrome`/`safari`/`iOS` uTLS fingerprints as suspicious while `firefox`/`edge`/`OkHttp` still pass. This reverses the old "use chrome" advice. Keep it a parameter — the safe value drifts over time.

## Execution mode note

All commands below assume **Remote mode** and run as **root over SSH** (`ssh root@{SERVER_IP}`). This is deliberate: root login is still enabled until the very end (finalize step), and running the panel API / xray binary as root avoids the non-interactive `sudo` password prompt that would otherwise hang.

For **Local mode** (Claude Code on the VPS), drop the `ssh root@{SERVER_IP}` wrapper and run the inner command directly with `sudo` where a normal shell is used, or as root.

## Step 1: Pre-checks

Port 443 must be free (some providers pre-install apache2/nginx):

```bash
ssh root@{SERVER_IP} "ss -tlnp | grep -E ':(443|8443) ' || echo 'ports free'"
```

If something listens on 443/8443, stop and disable it (`systemctl disable --now apache2` / `nginx`), otherwise the inbound binds silently fail.

Detect the panel scheme — **3x-ui defaults to plain HTTP**, HTTPS only if the admin enabled a cert. Guessing wrong makes every API call fail:

```bash
ssh root@{SERVER_IP} 'P={panel_port}; if curl -sk --max-time 5 "https://127.0.0.1:$P/{web_base_path}/" -o /dev/null 2>/dev/null; then echo "https"; else echo "http"; fi'
```

Save the result as `{PANEL_SCHEME}` (`http` or `https`). Use `-k` only matters for `https`; it is harmless on `http`.

## Step 2: Generate keys and identifiers

Generate the Reality keypair (shared by both inbounds). The xray binary lives at a globbed path; expand the glob **inside** a root shell so it resolves against root's permissions:

```bash
ssh root@{SERVER_IP} 'bash -c "/usr/local/x-ui/bin/xray-linux-* x25519"'
```

Output is **three** lines since Sept 2025 — `PrivateKey:`, `Password:`, `Hash32:`. Reality's public key is the **`Password`** value (xray's confusing naming). Save `PrivateKey` → `{PRIVATE_KEY}` and `Password` → `{PUBLIC_KEY}`. Ignore `Hash32`.

Two UUIDs (one per inbound) and short IDs:

```bash
ssh root@{SERVER_IP} 'bash -c "/usr/local/x-ui/bin/xray-linux-* uuid"'   # → {UUID_XHTTP}
ssh root@{SERVER_IP} 'bash -c "/usr/local/x-ui/bin/xray-linux-* uuid"'   # → {UUID_TCP}
ssh root@{SERVER_IP} "openssl rand -hex 8"                                # → {SID_XHTTP}
ssh root@{SERVER_IP} "openssl rand -hex 8"                                # → {SID_TCP}
ssh root@{SERVER_IP} "openssl rand -hex 6"                                # → {XPATH} (XHTTP path suffix)
```

Generate one subscription id shared by both clients (16 lowercase alphanumeric — pass it explicitly, or the API assigns an ugly UUID):

```bash
ssh root@{SERVER_IP} "tr -dc 'a-z0-9' </dev/urandom | head -c 16; echo"   # → {SUBID}
```

## Step 3: Choose SNI targets

Run the Reality scanner (see Step 4 below) to find masquerade domains on the VPS's own /24 subnet. You need **two** SNIs — one per inbound — ideally different, so a single blacklisted SNI doesn't take down both, and to spread the per-SNI connection-frequency that the June wave watches.

Keep `{best_sni}` for the XHTTP inbound and `{tcp_sni}` for the TCP inbound. Both must support TLS 1.3 + H2 + X25519 (the scanner guarantees this) and must NOT sit behind a CDN.

## Step 4: Reality SNI scanner (/24 subnet)

Scan the server's /24 for neighbours that support the exact TLS stack Reality mimics. A neighbour on the same hosting is ideal — DPI cannot distinguish your traffic from a real visit to that neighbour.

```bash
ssh root@{SERVER_IP} 'ARCH=$(dpkg --print-architecture); SA="$ARCH"; curl -fsSL "https://github.com/XTLS/RealiTLScanner/releases/latest/download/RealiTLScanner-linux-${SA}" -o /tmp/scanner && chmod +x /tmp/scanner && file /tmp/scanner | grep -q ELF || { echo "ERROR: scanner not a valid binary for $ARCH"; exit 1; }; MY_IP=$(curl -4 -fsS ifconfig.me); echo "$MY_IP" | grep -qE "^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$" || { echo "ERROR: could not detect IPv4"; exit 1; }; SUBNET=$(echo "$MY_IP" | sed "s/\.[0-9]*$/.0\/24/"); echo "Scanning $SUBNET"; timeout 120 /tmp/scanner -addr "$SUBNET" -thread 16 -timeout 5 2>&1 | head -200'
```

`dpkg --print-architecture` prints `amd64`/`arm64`, which are exactly the release-asset suffixes (`RealiTLScanner-linux-amd64` / `-arm64`) — no remap needed (older `linux-64`/`arm64-v8a` names 404). `curl -fsSL` (with `-f`) fails on a 404 instead of saving an HTML error page; the `file | grep ELF` check catches a bad download; `MY_IP` is validated as IPv4 before use. The scanner runs `-thread 16 -timeout 5` so it covers the whole /24 within the time budget instead of the stock 2 threads.

**Choosing SNIs** — every scanner hit already supports TLS 1.3+H2+X25519. Prefer, in order:
1. Small unknown neighbours on the same /24 (e.g. `shop.finn-auto.fi`) — not filtered, verified same-subnet.
2. Regional/niche services.
3. Well-known non-CDN tech sites (`github.com`, `twitch.tv`) — acceptable, less ideal.

**Avoid:** `www.google.com`, `www.microsoft.com`, `googletagmanager.com` (DPI-blacklisted); anything behind Cloudflare/Akamai/Fastly (IP won't match, active probing detects it); domains resolving to a different IP range than the VPS.

If the /24 is sparse (some OVH ranges), widen to /23:

```bash
ssh root@{SERVER_IP} 'MY_IP=$(curl -4 -fsS ifconfig.me); SUBNET=$(echo "$MY_IP" | sed "s/\.[0-9]*$/.0\/23/"); timeout 180 /tmp/scanner -addr "$SUBNET" -thread 16 -timeout 5 2>&1 | head -200'
```

Last-resort fallback if nothing is found: `www.yahoo.com` (TLS 1.3, many IPs, less filtered than google/microsoft). Always prefer a real scanned neighbour.

## Step 5: Log in to the panel API

```bash
ssh root@{SERVER_IP} 'P={panel_port}; curl -sk -c /tmp/3x-cookie -b /tmp/3x-cookie -X POST "{PANEL_SCHEME}://127.0.0.1:$P/{web_base_path}/login" -H "Content-Type: application/x-www-form-urlencoded" -d "username={panel_username}&password={panel_password}"'
```

The password reaches only the local panel over loopback. It is still visible in the server's process list for an instant — acceptable on a single-tenant VPS you control; on shared hosting, prefer creating the inbounds through the panel UI over an SSH tunnel (see `subscription.md` for the tunnel).

## Step 6: Create the primary XHTTP+Reality inbound (port 443)

```bash
ssh root@{SERVER_IP} 'P={panel_port}; curl -sk -c /tmp/3x-cookie -b /tmp/3x-cookie -X POST "{PANEL_SCHEME}://127.0.0.1:$P/{web_base_path}/panel/api/inbounds/add" -H "Content-Type: application/json" -d '"'"'{
  "up": 0, "down": 0, "total": 0,
  "remark": "vless-xhttp-reality",
  "enable": true, "expiryTime": 0, "listen": "", "port": 443,
  "protocol": "vless",
  "settings": "{\"clients\":[{\"id\":\"{UUID_XHTTP}\",\"flow\":\"\",\"email\":\"xhttp\",\"enable\":true,\"subId\":\"{SUBID}\",\"limitIp\":0,\"totalGB\":0,\"expiryTime\":0}],\"decryption\":\"none\",\"fallbacks\":[]}",
  "streamSettings": "{\"network\":\"xhttp\",\"security\":\"reality\",\"xhttpSettings\":{\"path\":\"/{XPATH}\",\"host\":\"\",\"mode\":\"stream-one\",\"xPaddingBytes\":\"100-1000\",\"scMaxEachPostBytes\":\"1000000\",\"scMaxBufferedPosts\":30,\"scStreamUpServerSecs\":\"20-80\",\"enableXmux\":true},\"realitySettings\":{\"show\":false,\"xver\":0,\"dest\":\"{best_sni}:443\",\"serverNames\":[\"{best_sni}\"],\"privateKey\":\"{PRIVATE_KEY}\",\"minClient\":\"\",\"maxClient\":\"\",\"maxTimediff\":0,\"shortIds\":[\"{SID_XHTTP}\"],\"settings\":{\"publicKey\":\"{PUBLIC_KEY}\",\"fingerprint\":\"firefox\",\"serverName\":\"\",\"spiderX\":\"/\"}}}",
  "sniffing": "{\"enabled\":false,\"destOverride\":[\"http\",\"tls\",\"quic\"],\"metadataOnly\":false,\"routeOnly\":false}"
}'"'"''
```

## Step 7: Create the hardened TCP+Reality+Vision fallback inbound (port 8443)

`flow` lives in the client object. `fingerprint=firefox`. `mldsa65Seed` is empty (post-quantum off — it only guards against future MITM on config leak, does nothing against DPI, and forces an RSA-cert dest ≥3500 bytes). Vision's built-in padding closes the May-2026 traffic-shape signature automatically.

```bash
ssh root@{SERVER_IP} 'P={panel_port}; curl -sk -c /tmp/3x-cookie -b /tmp/3x-cookie -X POST "{PANEL_SCHEME}://127.0.0.1:$P/{web_base_path}/panel/api/inbounds/add" -H "Content-Type: application/json" -d '"'"'{
  "up": 0, "down": 0, "total": 0,
  "remark": "vless-tcp-reality-vision",
  "enable": true, "expiryTime": 0, "listen": "", "port": 8443,
  "protocol": "vless",
  "settings": "{\"clients\":[{\"id\":\"{UUID_TCP}\",\"flow\":\"xtls-rprx-vision\",\"email\":\"tcp-vision\",\"enable\":true,\"subId\":\"{SUBID}\",\"limitIp\":0,\"totalGB\":0,\"expiryTime\":0}],\"decryption\":\"none\",\"fallbacks\":[]}",
  "streamSettings": "{\"network\":\"tcp\",\"security\":\"reality\",\"realitySettings\":{\"show\":false,\"xver\":0,\"dest\":\"{tcp_sni}:443\",\"serverNames\":[\"{tcp_sni}\"],\"privateKey\":\"{PRIVATE_KEY}\",\"minClient\":\"\",\"maxClient\":\"\",\"maxTimediff\":0,\"shortIds\":[\"{SID_TCP}\"],\"mldsa65Seed\":\"\",\"settings\":{\"publicKey\":\"{PUBLIC_KEY}\",\"fingerprint\":\"firefox\",\"serverName\":\"\",\"spiderX\":\"/\"}},\"tcpSettings\":{\"acceptProxyProtocol\":false,\"header\":{\"type\":\"none\"}}}",
  "sniffing": "{\"enabled\":false,\"destOverride\":[\"http\",\"tls\",\"quic\"],\"metadataOnly\":false,\"routeOnly\":false}"
}'"'"''
```

## Step 8: Open the firewall ports

```bash
ssh root@{SERVER_IP} "ufw allow 443/tcp && ufw allow 8443/tcp && ufw reload && ufw status"
```

(The subscription port is opened in `subscription.md`.)

## Step 9: Verify both inbounds bound

```bash
ssh root@{SERVER_IP} "x-ui status && ss -tlnp | grep -E ':(443|8443) '"
```

Both ports must be listening. If one is missing, check `x-ui log` — a bad SNI dest or an occupied port is the usual cause.

## Step 10: Get the connection links (reference)

The subscription (see `subscription.md`) is the primary delivery method. To sanity-check the raw links:

```bash
ssh root@{SERVER_IP} 'P={panel_port}; curl -sk -b /tmp/3x-cookie "{PANEL_SCHEME}://127.0.0.1:$P/{web_base_path}/panel/api/clients/subLinks/{SUBID}"'
```

This returns the JSON array of `vless://` links for both inbounds. For reference, they look like:

**XHTTP (primary):**
```
vless://{UUID_XHTTP}@{SERVER_IP}:443?type=xhttp&encryption=none&security=reality&pbk={PUBLIC_KEY}&fp=firefox&sni={best_sni}&sid={SID_XHTTP}&spx=%2F&path=%2F{XPATH}&mode=stream-one#vless-xhttp-reality
```

**TCP+Vision (iOS/fallback):**
```
vless://{UUID_TCP}@{SERVER_IP}:8443?type=tcp&encryption=none&security=reality&pbk={PUBLIC_KEY}&fp=firefox&sni={tcp_sni}&sid={SID_TCP}&spx=%2F&flow=xtls-rprx-vision#vless-tcp-reality
```

## Step 11: Clean up the session cookie

```bash
ssh root@{SERVER_IP} "rm -f /tmp/3x-cookie /tmp/scanner"
```

## Fallback: create inbounds through the panel UI

If the API path fails, open the panel over an SSH tunnel (see `subscription.md`) and add each inbound manually:
1. Inbounds → Add Inbound → Protocol VLESS.
2. XHTTP inbound: Port 443, Transport `xhttp`, mode `stream-one`, path `/{XPATH}`, no flow, Security Reality, fingerprint `firefox`, SNI = `{best_sni}`.
3. TCP inbound: Port 8443, Transport `tcp`, Flow `xtls-rprx-vision`, Security Reality, fingerprint `firefox`, SNI = `{tcp_sni}`.
4. Give both clients the same Subscription ID (`{SUBID}`).
