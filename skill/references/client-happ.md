# Client setup: Happ

Happ is an Xray-core-based client (the same core the server runs), which is why it supports Reality, XHTTP and Vision correctly. It replaced Hiddify as the recommended client for RU users in 2026.

## Install from official sources ONLY

There are many scam look-alikes (`happ-vpn.com`, `happvpn.ru`, `happguide.ru`, fake "Happ VPN" App Store clones) that ship malware or steal configs. Use only:

- **happ.su** / **happ.info** — official site
- **github.com/Happ-proxy** — official releases
- App Store / Google Play listing linked *from* happ.su (verify the developer, don't search blindly)

Tell the user explicitly: never download Happ from a link someone messaged them, and never from a site that isn't one of the above.

| Platform | Where |
|----------|-------|
| iOS / iPadOS | App Store (link via happ.su) |
| Android | Google Play or the APK on github.com/Happ-proxy |
| Windows | github.com/Happ-proxy releases |
| macOS | App Store or github.com/Happ-proxy |

## Import the subscription

1. Copy the subscription URL (`https://{SERVER_IP}:{sub_port}/{sub_path}/{SUBID}`).
2. In Happ: **+** → **Add subscription** (or "Import from URL") → paste → save.
3. Happ fetches and shows **two** servers: the XHTTP profile and the TCP/Vision profile.

## Which profile connects where

Both profiles are in one subscription on purpose:

- **Android / Windows / macOS** → use the **XHTTP (443)** profile first. It has the best DPI resistance. If a specific network blocks it, switch to the TCP profile.
- **iPhone / iPad** → use the **TCP/Vision (8443)** profile. **XHTTP+Reality does not work on Happ iOS** (Xray-core #5918: the Reality handshake completes but no data flows). This is not a config error — it is a known iOS limitation, and the reason the TCP profile exists. Selecting the XHTTP profile on iOS will just fail to pass traffic.

Happ can auto-select the working server, but on iOS pin the TCP profile manually to avoid it retrying the broken XHTTP one.

## Connect and verify

1. Tap the profile → connect.
2. Verify the exit IP is the server, not the user's ISP:
   - In-app: check the latency/ping shows green.
   - In a browser: open `https://ifconfig.me` — it must show `{SERVER_IP}`.
3. Confirm DNS isn't leaking: `https://browserleaks.com/dns` should show the server's resolver, not the local ISP.

## Auto-update

Because it's a subscription, when you later rotate an SNI or add a device, Happ re-fetches on its own schedule (or pull-to-refresh). The user doesn't re-import.

## Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| iOS connects but no internet | XHTTP profile selected on iOS | Switch to the TCP/Vision (8443) profile |
| "Handshake failed" / instant drop | SNI blacklisted or dest behind CDN | Re-scan SNIs (`reality-inbound.md` Step 4), update the inbound |
| Works on Wi-Fi, dead on mobile data | Mobile network is in whitelist mode | See `whitelist-and-fallbacks.md` — a foreign VPS cannot beat a whitelist |
| Subscription won't import | HTTPS cert invalid or port closed | Verify the LE-on-IP cert (`subscription.md` Step 2) and that `{sub_port}` is open in UFW |
| Connects, then frozen after ~15 KB | Old traffic-shape DPI signature | Confirm the TCP profile has `flow=xtls-rprx-vision` (padding); XHTTP should be immune |
| All profiles fail on one network only | That network blocks non-443, or DPI-froze the SNI | Try the 443 (XHTTP) profile; if still dead, rotate SNI and consider Hysteria2 (next step) |
