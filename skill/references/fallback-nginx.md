# Fallback Site (Nginx Stub)

Optional: makes server look like a regular website when someone visits the domain directly.

**ONLY for VLESS TLS path.** For Reality, the dest server (e.g., google.com) already acts as a built-in fallback -- visitors see the real website, no extra setup needed.

## When to Use

- User has VLESS TLS (with domain) and wants a custom fallback page
- Someone browsing to domain should see a normal-looking page, not "connection refused"
- Only works with VLESS TLS + TCP transport (NOT with Reality, NOT with XHTTP)

## Important Limitation

Fallback via 3x-ui works ONLY with transport TCP (not XHTTP). If XHTTP transport is needed, a full reverse proxy setup with Nginx is required (advanced, not covered here).

## Step 1: Install Nginx

```bash
ssh root@{SERVER_IP} "apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y nginx"
```

## Step 2: Configure Nginx on Localhost

Nginx must listen on localhost (not public), because port 443 is used by Xray.

```bash
ssh root@{SERVER_IP} "tee /etc/nginx/sites-available/stub << 'NGINX_EOF'
server {
    listen 127.0.0.1:8081;
    server_name _;

    root /var/www/html;
    index index.html;

    location / {
        try_files \$uri \$uri/ =404;
    }
}
NGINX_EOF
ln -sf /etc/nginx/sites-available/stub /etc/nginx/sites-enabled/stub && rm -f /etc/nginx/sites-enabled/default && nginx -t && systemctl reload nginx"
```

## Step 3: Create Stub HTML Page

Use a plain, benign landing page — **never a login/sign-in form**. A fake credential form is indistinguishable from a phishing page: it invites users to type real passwords, and security scanners flag it. A neutral "site is up" page achieves the same goal (a direct visitor sees a normal page, not "connection refused") without any of that risk.

```bash
ssh root@{SERVER_IP} 'tee /var/www/html/index.html << '"'"'HTML_EOF'"'"'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Welcome</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #f5f5f5; display: flex; justify-content: center; align-items: center; min-height: 100vh; color: #333; }
        .card { background: white; padding: 48px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.08); max-width: 480px; text-align: center; }
        .card h1 { font-size: 26px; margin-bottom: 12px; }
        .card p { color: #666; font-size: 15px; line-height: 1.6; }
    </style>
</head>
<body>
    <div class="card">
        <h1>It works!</h1>
        <p>This server is online. There is nothing to see here yet.</p>
    </div>
</body>
</html>
HTML_EOF'
```

Replace the copy with anything harmless you like (a portfolio, a blog, a company page) — the only rule is no fields that solicit credentials or personal data.

## Step 4: Add Fallback to VLESS Inbound

The VLESS inbound must use TCP transport (not XHTTP) and have a fallback configured.

Update the inbound via panel UI or API to add fallback destination `127.0.0.1:8081`.

Via SSH tunnel to panel:
1. Open inbound settings
2. Transport: TCP
3. Add Fallback: destination `127.0.0.1:8081`
4. Save

Or update via API -- modify the inbound's `settings` JSON to include:
```json
"fallbacks": [{"dest": "127.0.0.1:8081"}]
```

## Step 5: Verify

Open server IP/domain in browser:
```
https://{domain}:443
```

Should show the plain landing page.

## Notes

- The stub page is purely cosmetic -- login form does nothing
- Replace with any HTML you want (portfolio, blog, company page)
- Keep it simple and realistic -- avoid suspicious empty pages
- Remove `h2` from ALPN in inbound settings if using fallback (HTTP/2 doesn't work with Nginx in proxy mode without full SSL setup)
