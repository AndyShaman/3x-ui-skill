# Whitelists, the RU DPI landscape, and the fallback ladder

Read this to set honest expectations and to know what to try when a profile stops working. It is deliberately blunt: some things this skill builds cannot beat, and pretending otherwise wastes the user's time.

## Two things are being done to traffic in RU (2026)

**1. Blacklist DPI (what this skill defeats).** The censor inspects traffic and blocks what looks like a proxy. Reality hides the TLS handshake; XHTTP and Vision+padding hide the post-handshake behaviour. On home broadband and most Wi-Fi, this is the regime, and the two-inbound design here is built to pass it. Two detection waves matter:

- **May-2026 wave** — an ML classifier on traffic *shape* after the handshake (first-packet sizes, timing). Closed by `flow=xtls-rprx-vision` + padding on the TCP inbound; XHTTP sidesteps it by design.
- **June-2026 wave** — operates at the ClientHello, where padding is useless. Three aggregating triggers: (1) server subnet/ASN reputation (hosting ranges like Selectel, Yandex.Cloud, Cloud.ru are scored down), (2) TLS fingerprint — `chrome`/`safari`/`iOS` are now *suspicious*, `firefox`/`edge`/`OkHttp` still pass (this is why the inbounds default to `fingerprint=firefox`), (3) more than ~3 parallel connections to one SNI within 60s with <350ms spacing → a ~120s freeze. Since Nov 2025 there is also IP↔SNI correlation: a big-brand SNI announced from a foreign hosting ASN gets blocked.

**2. Whitelist mode (what this skill CANNOT defeat).** Default-deny at the network layer: packets to any IP **not** on an allow-list are dropped at the second hop, *before* any DPI runs. Introduced Sept 2025, by early 2026 active in ~68–71 regions (~90M people), mostly on **mobile** carriers; home broadband/wired is mostly still open. The allow-list is ~63k IPs (Yandex.Cloud, Timeweb, VK, Selectel, Beget top the list). Almost all UDP (QUIC, WireGuard, external DNS) is dead; TCP 80/443/22 pass.

## The hard truth about whitelists

A foreign VPS **cannot** bypass a whitelist by any protocol trick. Reality, XHTTP, Vision, fingerprints — all irrelevant when the packet never reaches DPI because your IP simply isn't on the list. Masquerade solves *"my traffic looks like a proxy"*; it does nothing for *"packets to your IP are dropped at the router."* If the user's mobile carrier is in whitelist mode, this server will be unreachable on that network, full stop.

The only architecture that works against a whitelist is a **cascade**: an entry node on a *whitelisted* RU IP (a VPS at Yandex.Cloud / Timeweb / VK / Selectel / Beget — inside the allow-list) that forwards to your foreign exit node. The RU node is reachable (it's whitelisted); it relays to abroad. That is a different, more expensive build (two servers, RU-side legal exposure) and out of scope here — but it is the honest answer to "why doesn't my VPN work on mobile data?"

Practical test to tell which regime the user is in: if the server works on home Wi-Fi but dies on mobile data, it's a whitelist, not DPI — no server-side change will fix it.

## SNI pool (blacklist DPI, for masquerade)

For a **foreign** VPS, prefer real neighbours found by the scanner (`reality-inbound.md` Step 4) — they beat any static list. If you must pick from memory, non-CDN sites with TLS 1.3+H2 that are less filtered: `github.com`, `twitch.tv`, `www.yahoo.com`. Avoid `www.google.com`, `www.microsoft.com`, `googletagmanager.com` (blacklisted), and anything behind Cloudflare/Akamai/Fastly (IP won't match).

For an **RU-side** node in a cascade, the masquerade SNI must itself be whitelisted so the ClientHello passes L7 filtering: `max.ru`, `vk.com`, `ya.ru`, `userapi.com`, `vkuser.net`, `storage.yandex.net`, `yastatic.net`.

## Fallback ladder — what to try, in order

When a client stops connecting, escalate:

1. **Switch profile.** XHTTP (443) ↔ TCP/Vision (8443). A network may block one transport but not the other.
2. **Re-scan and rotate the SNI.** A frozen/blacklisted SNI is the most common failure. Re-run the scanner, pick a fresh neighbour, update the inbound's `dest`/`serverNames`, hand out the updated subscription (the client auto-refetches).
3. **Reduce parallel connections to one SNI.** If the June wave is freezing you, giving the two inbounds *different* SNIs (already the default here) spreads the per-SNI connection frequency below the trigger.
4. **Confirm fingerprint.** Ensure both inbounds use `firefox`, not `chrome`. If `firefox` itself ever starts being flagged, try `edge`.
5. **Add Hysteria2 (the real diversification — documented next step).** Everything above lives on the same TLS/TCP detection plane. Hysteria2 runs over **UDP/QUIC** — a different plane entirely — so when TCP-Reality gets classified, a UDP protocol can still pass (on non-whitelist networks; UDP is dead under whitelist). The user chose not to add it yet to keep the build simple; it is the natural next inbound if DPI tightens. It needs its own UDP port opened in UFW and a Hysteria2-capable client profile.
6. **If on mobile data and nothing works → whitelist.** Stop trying server-side fixes; see the cascade note above.

## Why not just use a well-known SNI or a CDN?

- Well-known brand SNI (google/microsoft) → blacklisted, and IP↔SNI correlation flags a big brand coming from a hosting ASN.
- CDN front (Cloudflare) → incompatible with Reality (point-to-point), and active probing detects the mismatch. Reality's whole security model is that the `dest` IP genuinely serves that SNI.
