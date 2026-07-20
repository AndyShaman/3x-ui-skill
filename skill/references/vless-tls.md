# VLESS TLS Setup (with Domain)

Optional alternative to Reality — use only when the user **has a domain** and specifically wants classic VLESS+TLS instead of the Reality build. The default, recommended path is Reality (`reality-inbound.md`); it needs no domain and resists DPI better. This file is kept for completeness.

Like the rest of setup, commands run as **root over SSH** (`ssh root@{SERVER_IP}`) to avoid non-interactive `sudo` prompts hanging.

## Prerequisites

- Domain registered and A-record pointing to server IP
- DNS propagated (verify: `nslookup {domain}` returns server IP)
- Ports 80 and 443 open in UFW (already done in server setup)

## Step 1: Verify DNS

```bash
ssh root@{SERVER_IP} "apt-get install -y dnsutils >/dev/null 2>&1; nslookup {domain}"
```

Must return the server IP. If not — wait 5-10 minutes for DNS propagation.

## Step 2: Get SSL Certificate

Easiest is the x-ui built-in menu:

```bash
ssh -t root@{SERVER_IP} "x-ui"
```

Choose **SSL Certificate Management → Get SSL Certificate**, enter the domain, use port 80.

Non-interactive alternative with acme.sh. First collect `{user_email}` — any address you control; acme.sh uses it only to register the ACME account. Run as root so `~` resolves to `/root`; register an account (ZeroSSL/Let's Encrypt now require it) and pin Let's Encrypt as the CA:

```bash
ssh root@{SERVER_IP} "apt-get install -y socat >/dev/null 2>&1; curl https://get.acme.sh | sh -s email={user_email}; ~/.acme.sh/acme.sh --set-default-ca --server letsencrypt; ~/.acme.sh/acme.sh --issue -d {domain} --standalone --httpport 80; mkdir -p /root/cert/{domain}; ~/.acme.sh/acme.sh --install-cert -d {domain} --key-file /root/cert/{domain}/privkey.pem --fullchain-file /root/cert/{domain}/fullchain.pem --reloadcmd 'x-ui restart'"
```

Certificate files land at:
```
/root/cert/{domain}/fullchain.pem   # certificate
/root/cert/{domain}/privkey.pem     # private key
```

## Step 3: Configure Panel with SSL

```bash
ssh root@{SERVER_IP} "x-ui cert -webCert /root/cert/{domain}/fullchain.pem -webCertKey /root/cert/{domain}/privkey.pem && x-ui restart"
```

Panel now serves HTTPS. Access via SSH tunnel (never open the panel port publicly):

```bash
ssh -L {panel_port}:127.0.0.1:{panel_port} {nickname}
```

Then open `https://127.0.0.1:{panel_port}/{web_base_path}` (accept the certificate warning over the tunnel).

## Step 4: Change Panel Credentials

Prefer setting these in the panel UI over the tunnel. If using the CLI, note the password is briefly visible in the server process list — acceptable on a single-tenant VPS:

```bash
ssh root@{SERVER_IP} "x-ui setting -username {new_username} -password {new_password} && x-ui restart"
```

## Step 5: Enable 2FA in Panel (Recommended)

Over the tunnel: Settings → Account → enable Two-Factor Authentication, scan the QR with an authenticator app, confirm the 6-digit code.

## Step 6: Create VLESS TLS Inbound

Login to the API (panel is HTTPS after Step 3):

```bash
ssh root@{SERVER_IP} 'P={panel_port}; curl -sk -c /tmp/3x-cookie -b /tmp/3x-cookie -X POST "https://127.0.0.1:${P}/{web_base_path}/login" -H "Content-Type: application/x-www-form-urlencoded" -d "username={panel_username}&password={panel_password}"'
```

Generate a UUID and a subscription id (expand the glob inside a root shell — M6). Save both — the API body and the connection link below use them verbatim:

```bash
ssh root@{SERVER_IP} 'bash -c "/usr/local/x-ui/bin/xray-linux-* uuid"'   # → {CLIENT_UUID}
ssh root@{SERVER_IP} "tr -dc 'a-z0-9' </dev/urandom | head -c 16; echo"   # → {SUBID}
```

Create the VLESS TLS inbound on port 443:

```bash
ssh root@{SERVER_IP} 'P={panel_port}; curl -sk -c /tmp/3x-cookie -b /tmp/3x-cookie -X POST "https://127.0.0.1:${P}/{web_base_path}/panel/api/inbounds/add" -H "Content-Type: application/json" -d '"'"'{
  "up": 0,
  "down": 0,
  "total": 0,
  "remark": "vless-tls",
  "enable": true,
  "expiryTime": 0,
  "listen": "",
  "port": 443,
  "protocol": "vless",
  "settings": "{\"clients\":[{\"id\":\"{CLIENT_UUID}\",\"flow\":\"xtls-rprx-vision\",\"email\":\"user1\",\"limitIp\":0,\"totalGB\":0,\"expiryTime\":0,\"enable\":true,\"subId\":\"{SUBID}\"}],\"decryption\":\"none\",\"fallbacks\":[]}",
  "streamSettings": "{\"network\":\"tcp\",\"security\":\"tls\",\"externalProxy\":[],\"tlsSettings\":{\"serverName\":\"{domain}\",\"minVersion\":\"1.2\",\"maxVersion\":\"1.3\",\"cipherSuites\":\"\",\"rejectUnknownSni\":false,\"disableSystemRoot\":false,\"enableSessionResumption\":false,\"certificates\":[{\"certificateFile\":\"/root/cert/{domain}/fullchain.pem\",\"keyFile\":\"/root/cert/{domain}/privkey.pem\",\"ocspStapling\":3600,\"oneTimeLoading\":false,\"usage\":\"encipherment\",\"buildChain\":false}],\"alpn\":[\"h2\",\"http/1.1\"]},\"tcpSettings\":{\"acceptProxyProtocol\":false,\"header\":{\"type\":\"none\"}}}",
  "sniffing": "{\"enabled\":true,\"destOverride\":[\"http\",\"tls\",\"quic\",\"fakedns\"],\"metadataOnly\":false,\"routeOnly\":false}",
  "allocate": "{\"strategy\":\"always\",\"refresh\":5,\"concurrency\":3}"
}'"'"''
```

## Step 7: Get Connection Link

The link uses `fp=firefox` — the June-2026 DPI wave flags `chrome`/`safari` fingerprints:

```
vless://{CLIENT_UUID}@{domain}:443?type=tcp&security=tls&sni={domain}&fp=firefox&flow=xtls-rprx-vision#vless-tls
```

If you enabled the subscription (`subscription.md`) and gave this client the shared `{SUBID}`, the link is served through the subscription URL alongside the Reality profiles.

## Step 8: Auto-Renew Certificate

acme.sh installs a root cron job for renewal. Verify:

```bash
ssh root@{SERVER_IP} "crontab -l 2>/dev/null | grep acme"
```

Should show an acme.sh renewal entry. Keep port 80 open for the renewal challenge.

## Completion

After getting the link, continue to the client section (`client-happ.md`) to install Happ and import the connection.
