# Design — wp-bot-forensics

Detect and classify automated traffic in the real Apache access logs of a
WordPress site (site.example), with explainable rules first and an anomaly
detector as a safety net.

## Data

- **Source**: Apache `combined` access logs of site.example (WordPress behind
  Cloudflare and Traefik, real client IPs restored by `mod_remoteip`),
  archived daily on the server since 2026-10-13.
- **Not versioned**: raw logs (`data/raw/`). A one-day pseudonymised sample is
  versioned in `data/sample/` for CI and public demo.
- **WP Cerber exports** (`data/raw/cerber/`, not versioned): activity log
  (events and Cerber verdicts: lockouts, forbidden URLs, vulnerable-code scans,
  refused form submissions, login failures) and HTTP requests log, both since
  2026-09-28. Timestamps read from the `Unix Timestamp` column (display dates
  are localised).
- **Enrichment**: [DB-IP IP to ASN Lite](https://db-ip.com/db/download/ip-to-asn-lite)
  (CC BY 4.0, attribution in `NOTICE`).
- **Optional (day 3)**: [SecRepo self.logs](https://www.secrepo.com/self.logs/)
  (CC BY 4.0, same format) to check that rules generalise and to get a human
  baseline.
- **Privacy**: IPs are replaced by HMAC-SHA256 (secret key from `.env`) at parse
  time, after ASN/country lookup. No clear IP reaches Elasticsearch, Parquet or
  screenshots. The site name is a config value so it can be anonymised in one line.
  Usernames are hashed the same way, and the site's custom login URL is a
  security secret: it is replaced by `/<custom-login>/` everywhere (case-insensitive,
  also when percent-encoded). Author archive paths expose usernames:
  `/author/<name>` becomes `/author/<author>` in paths, referers and Cerber URLs.

## Known biases

- Cloudflare caches HTML and assets: few humans reach the origin, so the bot
  share is high by construction and the HTML/asset ratio is a weak signal.
- 78 % of requests are already refused (403) by server hardening and WP Cerber:
  the analysis measures attacker intent, not successful intrusions.
- Part of the traffic is our own (uptime monitors, WP-cron, admin sessions) and
  is classified as `internal`, excluded from the bot share.
- Each defence layer sees part of the traffic: Apache rejects most `xmlrpc.php`
  POSTs (5,629 in Apache logs) before PHP runs, so Cerber logs only 19 XML-RPC
  refusals. Cross-referencing both is a finding in itself (README section
  "What each defence layer sees").

## Pipeline

```
data/raw/*.log.gz              data/raw/cerber/*.csv
  → parse        (regex, malformed lines counted, never dropped silently)
                                 → parse_cerber → ES: cerber-events, per-IP cerber_verdict
  → enrich       (ASN, country, path category, UA family, pseudonymised IP)
  → features     (per IP)
  → rules + Isolation Forest
  → Elasticsearch: weblogs-requests (1 doc / request), weblogs-actors (1 doc / IP)
  → Parquet: data/processed/  → DuckDB analysis
```

- Unit of analysis: the IP (scanners rotate user-agents, which breaks
  (IP, UA) sessions). Rates use 1-minute and 10-minute windows.
- Two indexes = events vs. entities, as in a SOC.

## Indicators (per IP)

| # | Indicator | Rationale |
|---|---|---|
| 1 | Peak requests per minute | Humans rarely exceed a few pages per minute. |
| 2 | Inter-arrival coefficient of variation | Scripted sleeps give metronomic timing. |
| 3 | 4xx and 403 rate | Scanners request paths that do not exist or are forbidden. |
| 4 | Sensitive path probes (`.env`, `.git`, `wp-config`, webshell names) | No human requests `/.env`. |
| 5 | POST bursts on `xmlrpc.php` / `wp-login.php` (10 min) | Brute force / credential stuffing signature. |
| 6 | Distributed campaigns: same UA and target across IPs in a window | Stuffing spreads attempts to stay under per-IP limits. |
| 7 | UA missing, tool (`curl`, `python-requests`…) or outdated browser | Bot kits freeze a UA; browsers auto-update. |
| 8 | Declared bot vs. ASN (Googlebot from Google, Jetpack from Automattic) | Claiming a name is free, owning the IP is not. |
| 9 | Datacenter ASN (explicit hosting providers only) | Real visitors browse from ISPs, not cloud servers. Evidence only: never enough on its own to call an actor a bot. |
| 10 | `robots.txt` / sitemap reads | Only crawlers read them (declared, polite bots). |
| 11 | No referer on HTML pages | Humans arrive from links or search engines. |
| 12 | Night activity in local time (UTC+11) | Weak signal, used as support only. |
| 13 | Refused form submissions (Cerber) / repeated contact-form POSTs | Form spam, a cousin of fake sign-ups. |
| — | HTML / asset ratio | Kept with low weight because of CDN caching. |

Dropped: sequential product browsing (no catalogue on this site), replaced by #10.

## Classification

Rules are applied in order; each returns its reasons (e.g.
`["xmlrpc_post_10min=48", "asn=datacenter"]`), stored with the verdict.

1. `internal` — operator IPs from `INTERNAL_IPS` (secret, in `.env`) are classified
   `internal` first, whatever they do; before this allowlist the operator's admin
   sessions (45 req/min, `generic_bot`) and SEO audit (`vuln_scanner`) were flagged,
   kept as a validation finding. Then own monitors, WP-cron, admin (only when no
   attack signal fires)
2. `credential_attack` — indicators 5–6
3. `vuln_scanner` — indicators 3–4
4. `spoofed_crawler` — declared bot, inconsistent ASN
5. `form_spam` — indicator 13 (wins over a verified crawler identity)
6. `verified_crawler` — declared bot from its operator's network (only when no attack
   or form signal fires)
7. `generic_bot` — tool/missing UA, outdated browser, abnormal rhythm, or a declared bot
   that cannot be verified (reason `declared=<name>(unverified)`). A datacenter network
   is recorded as a reason but is not sufficient on its own.
8. `unknown` — everything else (probable human)

**Crawler verification** means "comes from a known operator network": the declared
name must be in the bot → ASN table and the IP's AS organisation must match it.
A declared bot outside that table, or without AS information, is a `generic_bot`
(declared, unverified), not a verified crawler. The ASN check is necessary but not
sufficient: a rented Google Cloud VM is also "Google LLC". Matching the operators'
published crawler IP ranges (or reverse-DNS) is future work.

A declared bot name is a product token in the user-agent (`EvilBot/1.0`,
`Foo Spider)`), never a word inside a URL (`+http://ahrefs.com/robot/`) nor the
CUBOT phone brand.

Attack behaviour is ranked before identity claims, because a declared crawler name is
trivially spoofed (e.g. a fake "Jetpack" UA used for XML-RPC credential stuffing); the
spoofing remains visible in the stored reasons.

Isolation Forest on log-scaled indicators surfaces `unknown` IPs that look
automated, to improve rules. It never overrides a rule.

**Validation** (no ground truth): manual review of 30 random actors, rule vs.
Isolation Forest agreement table, consistency with server 403s and with the
per-IP Cerber verdict.

## Stack

- `docker-compose.yml`: Elasticsearch 8 + Kibana 8, single node, security on,
  setup container sets the `kibana_system` password; secrets in `.env`
  (`.env.example` versioned).
- Python 3 package `botforensics` (`python -m botforensics ingest <dir>`),
  explicit mappings in `src/botforensics/mappings/`, bulk indexing.
- SQL: **DuckDB** for versioned analysis (standard SQL on Parquet, runs in CI
  without a cluster); **ES|QL** for a few investigation queries in Kibana.
- Kibana dashboard exported to `kibana/dashboard.ndjson`, imported by
  `scripts/import_dashboard.py`: traffic volume, estimated bot share, top
  suspicious IPs / UAs / ASNs, attack timeline.
- Quality: `pytest` (parse, features, rules), `ruff`, GitHub Actions CI.

## Run

```
docker compose up -d
python -m botforensics ingest data/sample
python scripts/import_dashboard.py
```

## Scope cuts, in order, if time runs out

SecRepo (out of scope unless time is left) → Isolation Forest → indicator 6.
