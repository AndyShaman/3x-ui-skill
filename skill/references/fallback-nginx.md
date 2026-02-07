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
ssh {nickname} "sudo apt update && sudo apt install -y nginx"
```

## Step 2: Configure Nginx on Localhost

Nginx must listen on localhost (not public), because port 443 is used by Xray.

```bash
ssh {nickname} "sudo tee /etc/nginx/sites-available/stub << 'NGINX_EOF'
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
sudo ln -sf /etc/nginx/sites-available/stub /etc/nginx/sites-enabled/stub && sudo rm -f /etc/nginx/sites-enabled/default && sudo nginx -t && sudo systemctl reload nginx"
```

## Step 3: Create Stub HTML Page

Generate a realistic-looking page. Example -- fake cloud login:

```bash
ssh {nickname} 'sudo tee /var/www/html/index.html << '"'"'HTML_EOF'"'"'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Cloud Storage</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #f5f5f5; display: flex; justify-content: center; align-items: center; min-height: 100vh; }
        .login-box { background: white; padding: 40px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); width: 360px; }
        .login-box h1 { font-size: 24px; margin-bottom: 8px; color: #333; }
        .login-box p { color: #666; margin-bottom: 24px; font-size: 14px; }
        .login-box input { width: 100%; padding: 12px; margin-bottom: 16px; border: 1px solid #ddd; border-radius: 4px; font-size: 14px; }
        .login-box input:focus { outline: none; border-color: #0070f3; }
        .login-box button { width: 100%; padding: 12px; background: #0070f3; color: white; border: none; border-radius: 4px; font-size: 14px; cursor: pointer; }
        .login-box button:hover { background: #005bb5; }
        .login-box .footer { margin-top: 16px; text-align: center; font-size: 12px; color: #999; }
    </style>
</head>
<body>
    <div class="login-box">
        <h1>Cloud Storage</h1>
        <p>Sign in to access your files</p>
        <form onsubmit="return false;">
            <input type="email" placeholder="Email" autocomplete="off">
            <input type="password" placeholder="Password" autocomplete="off">
            <button type="submit">Sign In</button>
        </form>
        <div class="footer">Secure cloud storage service</div>
    </div>
</body>
</html>
HTML_EOF'
```

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

Should show the fake cloud login page.

## Notes

- The stub page is purely cosmetic -- login form does nothing
- Replace with any HTML you want (portfolio, blog, company page)
- Keep it simple and realistic -- avoid suspicious empty pages
- Remove `h2` from ALPN in inbound settings if using fallback (HTTP/2 doesn't work with Nginx in proxy mode without full SSL setup)
