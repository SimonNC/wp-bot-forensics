# Threat report — automated traffic on a WordPress origin, 13–20 Oct 2026

*Written as for a customer. Site anonymised as `site.example`. Evidence and code in this
repository; every figure is reproduced by `python -m botforensics report`.*

## Summary

Over one week, **98.7 % of the requests reaching the origin server were automated**
(27,864 requests, 863 IPs). Two campaigns stand out: **password attacks routed through a
residential proxy network**, and **secrets scanners disguised as AI and search crawlers**.
Server hardening blocked both: every XML-RPC login attempt was refused and no secret was
served. The
risk is what changes next: the same tools would get through if they adopted a believable
browser identity or targeted a less hardened endpoint.

## Finding 1 — Account takeover attempts through residential proxies

| | |
|---|---|
| Scale | 43 IPs, 5,160 login attempts on `POST /xmlrpc.php`, 13–20 Oct |
| Sources | 34 consumer and mobile ISPs in 21 countries (16 IPs in India); none in a datacenter |
| Disguise | 39 IPs claim to be WordPress.com's Jetpack service; none from its network |
| Tool fingerprint | ~56 attempts per 10 min per IP, near-constant timing (median CV 0.05); 25 IPs stop at exactly 150 attempts |
| Outcome | All 5,189 XML-RPC POSTs refused (403) by the web server |

**Assessment.** A single tool distributing attempts over a rented residential proxy
network to stay under per-IP limits. Blocking IPs would hurt real users behind the same
carrier-grade NAT and would not stop the attacker. Request bodies are not logged, so
credential stuffing (leaked pairs) cannot be told apart from brute force.

## Finding 2 — Secrets scanners wearing AI crawler identities

| | |
|---|---|
| Scale | 6 IPs, 2,513 requests, 4 separate days |
| Sources | Google Cloud, 6 regions (TW, NL, CA, US, JP ×2) |
| Disguise | The same 33 user-agents per IP: 24 crawler names (GPTBot, ClaudeBot, PerplexityBot, DeepSeekBot, GrokBot, Googlebot…) |
| Targets | `/.env`, `/.env.production`, `/@fs/.env`, `/api/proc/self/environ`, cloud credential files |
| Tool fingerprint | ~400 requests in 12–14 s; four IPs with exactly 219 × 403 |
| Outcome | Only the home page and `robots.txt` answered 200; nothing sensitive served |

**Assessment.** Not AI agent traffic: a secrets scanner rotating crawler identities,
probably to pass "allow AI crawlers" rules. Because it runs from Google Cloud, its
`Googlebot` claim passes a check based on the network owner alone.

## Recommended detection signals

1. **Identity vs. network.** A declared crawler must match its operator's published IP
   ranges or forward-confirmed reverse DNS, not just the AS name. Would have flagged all
   6 scanners and all 39 fake Jetpack clients.
2. **Identity rotation.** More than a handful of distinct crawler names from one IP in a
   short window is never legitimate (here: 24 names in 12 s).
3. **Login velocity per target, across IPs.** Count authentication attempts per endpoint
   over sliding windows, not only per IP; add a per-client quota fingerprint (150).

## Limits of this analysis

Origin logs only: no TLS fingerprint, header order or JavaScript signal, so a consistent
headless browser behind a residential proxy would not be caught here. One small site
behind a CDN, one week. Classifier precision measured on 30 hand-reviewed actors (24/25
correct accusations); recall not yet measured.
