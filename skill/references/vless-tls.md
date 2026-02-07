# VLESS TLS Setup (with Domain)

Use this when user has a domain and wants VLESS TLS instead of Reality.

## Prerequisites

- Domain registered and A-record pointing to server IP
- DNS propagated (verify: `nslookup {domain}` returns server IP)
- Ports 80 and 443 open in UFW (already done in Step 8)

## Step 1: Verify DNS

```bash
nslookup {domain}
```

Must return the server IP. If not -- wait 5-10 minutes for DNS propagation.

Can also check from server:
```bash
ssh {nickname} "sudo apt install -y dnsutils > /dev/null 2>&1; nslookup {domain}"
```

## Step 2: Get SSL Certificate

Use x-ui built-in cert management:

```bash
ssh {nickname} "sudo x-ui cert"
```

This opens interactive menu. Select:
1. "Get SSL" (option 1)
2. Enter domain name
3. Use port 80 (default)

Alternatively, non-interactive with acme.sh:

```bash
ssh {nickname} "sudo apt install -y socat && curl https://get.acme.sh | sh && sudo ~/.acme.sh/acme.sh --issue -d {domain} --standalone --httpport 80 && sudo ~/.acme.sh/acme.sh --install-cert -d {domain} --key-file /root/cert/{domain}/privkey.pem --fullchain-file /root/cert/{domain}/fullchain.pem --reloadcmd 'x-ui restart'"
```

Certificate files will be at:
```
/root/cert/{domain}/fullchain.pem   # certificate
/root/cert/{domain}/privkey.pem     # private key
```

## Step 3: Configure Panel with SSL

Apply certificate to panel:

```bash
ssh {nickname} "sudo /usr/local/x-ui/x-ui cert -webCert /root/cert/{domain}/fullchain.pem -webCertKey /root/cert/{domain}/privkey.pem"
ssh {nickname} "sudo x-ui restart"
```

Panel now serves HTTPS. Access via SSH tunnel:

```bash
ssh -L {panel_port}:127.0.0.1:{panel_port} {nickname}
```

Then open: `https://127.0.0.1:{panel_port}/{web_base_path}` (browser will warn about certificate mismatch -- this is expected, accept it).

## Step 4: Change Panel Credentials

Connection is encrypted (SSH tunnel + HTTPS), safe to set custom credentials:

```bash
ssh {nickname} "sudo x-ui setting -username {new_username} -password {new_password}"
ssh {nickname} "sudo x-ui restart"
```

## Step 5: Enable 2FA in Panel (Recommended)

Tell user to:
1. Open panel via SSH tunnel: `https://127.0.0.1:{panel_port}/{web_base_path}`
2. Go to Settings -> Account
3. Enable "Two-Factor Authentication"
4. Scan QR with authenticator app (Google Authenticator, Microsoft Authenticator)
5. Enter 6-digit code to confirm

## Step 6: Create VLESS TLS Inbound

Login to API:

```bash
ssh {nickname} 'PANEL_PORT={panel_port}; curl -s -c /tmp/3x-cookie -b /tmp/3x-cookie -X POST "http://127.0.0.1:${PANEL_PORT}/{web_base_path}/login" -H "Content-Type: application/x-www-form-urlencoded" -d "username={panel_username}&password={panel_password}"'
```

Generate UUID:

```bash
ssh {nickname} "sudo /usr/local/x-ui/bin/xray-linux-* uuid"
```

Create VLESS TLS inbound on port 443:

```bash
ssh {nickname} 'PANEL_PORT={panel_port}; curl -s -c /tmp/3x-cookie -b /tmp/3x-cookie -X POST "http://127.0.0.1:${PANEL_PORT}/{web_base_path}/panel/api/inbounds/add" -H "Content-Type: application/json" -d '"'"'{
  "up": 0,
  "down": 0,
  "total": 0,
  "remark": "vless-tls",
  "enable": true,
  "expiryTime": 0,
  "listen": "",
  "port": 443,
  "protocol": "vless",
  "settings": "{\"clients\":[{\"id\":\"{CLIENT_UUID}\",\"flow\":\"xtls-rprx-vision\",\"email\":\"user1\",\"limitIp\":0,\"totalGB\":0,\"expiryTime\":0,\"enable\":true}],\"decryption\":\"none\",\"fallbacks\":[]}",
  "streamSettings": "{\"network\":\"tcp\",\"security\":\"tls\",\"externalProxy\":[],\"tlsSettings\":{\"serverName\":\"{domain}\",\"minVersion\":\"1.2\",\"maxVersion\":\"1.3\",\"cipherSuites\":\"\",\"rejectUnknownSni\":false,\"disableSystemRoot\":false,\"enableSessionResumption\":false,\"certificates\":[{\"certificateFile\":\"/root/cert/{domain}/fullchain.pem\",\"keyFile\":\"/root/cert/{domain}/privkey.pem\",\"ocspStapling\":3600,\"oneTimeLoading\":false,\"usage\":\"encipherment\",\"buildChain\":false}],\"alpn\":[\"h2\",\"http/1.1\"]},\"tcpSettings\":{\"acceptProxyProtocol\":false,\"header\":{\"type\":\"none\"}}}",
  "sniffing": "{\"enabled\":true,\"destOverride\":[\"http\",\"tls\",\"quic\",\"fakedns\"],\"metadataOnly\":false,\"routeOnly\":false}",
  "allocate": "{\"strategy\":\"always\",\"refresh\":5,\"concurrency\":3}"
}'"'"''
```

## Step 7: Get Connection Link

```bash
ssh {nickname} 'PANEL_PORT={panel_port}; curl -s -b /tmp/3x-cookie "http://127.0.0.1:${PANEL_PORT}/{web_base_path}/panel/api/inbounds/list" | python3 -c "
import json,sys
data = json.load(sys.stdin)
for inb in data.get(\"obj\", []):
    if inb.get(\"protocol\") == \"vless\" and \"tls\" in inb.get(\"streamSettings\", \"\"):
        settings = json.loads(inb[\"settings\"])
        stream = json.loads(inb[\"streamSettings\"])
        client = settings[\"clients\"][0]
        uuid = client[\"id\"]
        port = inb[\"port\"]
        sni = stream.get(\"tlsSettings\", {}).get(\"serverName\", \"\")
        flow = client.get(\"flow\", \"\")
        link = f\"vless://{uuid}@{sni}:{port}?type=tcp&security=tls&sni={sni}&fp=chrome&flow={flow}#vless-tls\"
        print(link)
        break
"'
```

## Step 8: Auto-Renew Certificate via Crontab

Certificate renews automatically via acme.sh cron job. But ensure port 80 stays open (already done by server-setup).

Verify auto-renewal is configured:

```bash
ssh {nickname} "sudo crontab -l 2>/dev/null | grep acme"
```

Should show a cron entry for acme.sh renewal.

## Completion

After getting the link, return to main SKILL.md Step 20 (Install Hiddify).
