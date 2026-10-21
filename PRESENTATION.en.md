# Presentation — wp-bot-forensics

Outline of a 5-minute talk, followed by the questions a Threats Research analyst might
ask. All figures come from [`analysis/FINDINGS.md`](analysis/FINDINGS.md).

## 5-minute talk

### 1. Context (0:00 – 0:40)

- One week of real Apache logs (13–20 October 2026) from a small business's WordPress
  site, in production behind Cloudflare. The site is anonymised.
- The question: **who still reaches the origin server, and what can an analyst prove from
  raw logs alone?**
- 27,864 requests, 863 IP addresses, 78 % answered with a 403.

### 2. Method (0:40 – 1:30)

- Python pipeline: parsing, ASN and country enrichment, HMAC pseudonymisation of IPs,
  per-IP indicators, then classification.
- **Explainable rules first.** Every verdict keeps its reasons, e.g.
  `declared=Jetpack; Jetpack_from=Reliance Jio; login_posts_10min=56`.
- Two principles: **behaviour beats declared identity** (a crawler name costs nothing), and
  **a datacenter is evidence, never a verdict**.
- Elasticsearch and Kibana for investigation; DuckDB for versioned SQL.

### 3. Finding 1: password attacks through residential proxies (1:30 – 2:30)

*Show the networks panel of the dashboard.*

- 43 IPs on consumer and mobile ISPs in 21 countries, **none in a datacenter**: most likely
  a rented residential proxy network.
- 5,160 login attempts on `xmlrpc.php`. 39 of these IPs pose as WordPress.com's Jetpack
  service; none comes from its network.
- The fingerprint of one tool: about 56 attempts per 10 minutes, near-constant timing, and
  25 IPs that stop at exactly 150 attempts, a per-bot quota.
- These are account takeover attempts. Without request bodies, I cannot tell credential
  stuffing from brute force.

### 4. Finding 2: scanners disguised as AI crawlers (2:30 – 3:20)

- 6 Google Cloud IPs, over 4 days, rotate the same 33 user-agents: GPTBot, ClaudeBot,
  PerplexityBot, DeepSeekBot, Googlebot… 24 crawler names in all.
- About 400 requests in 12–14 seconds per IP, all hunting for `.env` files and cloud
  credentials. Nothing sensitive was served.
- This is not AI agent traffic: it is a secrets scanner wearing crawler masks, probably to
  slip through "allow AI crawlers" rules.
- Lesson for my own detection: from Google Cloud, their fake Googlebot would have passed my
  ASN-based check. It is the first limit I would fix.

### 5. Validation and limits (3:20 – 4:30)

- No ground truth: manual review of 30 actors sampled by category. The rules agree with me
  on **25 out of 30**. When a rule flags a bot it is right 24 times out of 25; 4 of the 5
  actors left as `unknown` were bots. Precision is good, recall is the weak spot.
- One false positive found and fixed: my own admin sessions were classified as a bot.
- Each layer sees only part of the attack: Apache refuses all 5,189 XML-RPC POSTs, the
  security plugin logs only 14 of them.
- Above all: origin logs have no TLS fingerprint and no JavaScript signal. A headless
  Chrome behind a residential proxy would look human here. Those signals live upstream,
  at the edge.

### 6. Wrap-up (4:30 – 5:00)

- Next steps: published IP ranges and reverse DNS for crawlers, measuring recall with a
  second annotator.
- What I take from it for the role: start from raw data, explain every verdict, and measure
  honestly where the rules are wrong.

## Questions from a DataDome analyst

### 1. "Isn't your validation circular?"

- Partly, yes: I labelled, alone, actors classified by my own rules.
- What it still measures: precision per category (24 correct accusations out of 25). The
  error was a genuine Bingbot classified as a scanner for a single probe.
- What it does not measure: recall. And agreement on `unknown` is only 1 in 5.
- Next step: a second annotator, and a sample drawn from `unknown` to measure recall.
- A real false positive found along the way: my admin sessions at 45 requests per minute.
  "Fast and from one IP" does not mean "malicious".

### 2. "What does your pipeline do against an up-to-date headless Chrome, behind a residential proxy, with a consistent user-agent?"

- Nothing, and the README says so. Origin logs contain no TLS, no JavaScript, no header
  order.
- The edge layer sees those: TLS fingerprint, HTTP header consistency, client-side
  JavaScript signals, and the view of the same attacker across many sites.
- What my logs still bring: behaviour over time. The 150-attempt quota or the rotation of
  33 user-agents are tool fingerprints that survive an IP change.

### 3. "Who wrote the code? Walk me through `rules.py`."

- I built it with Claude Code, and the README says so. I chose the indicators, the rule
  order and the thresholds, reviewed 30 actors, and found and fixed the false positive on
  my admin sessions.
- One choice I defend: attack rules run before identity checks. That is why the fake
  GPTBot and ClaudeBot come out as `vuln_scanner`, not `spoofed_crawler`; the spoofing
  stays visible in the reasons and in a dedicated table in `FINDINGS.md`.

### 4. "How would you properly verify a Googlebot or an AI crawler?"

- Today I check that the IP belongs to the operator's network (AS "Google LLC"). That is
  necessary but not sufficient: the disguised scanners came precisely from Google Cloud,
  which is also "Google LLC".
- The right method: reverse DNS on the IP (`*.googlebot.com`), then forward DNS to confirm
  it resolves back to the same IP, or a match against the IP ranges operators publish
  (Google, Bing and OpenAI do).
- And behavioural consistency: a real crawler does not request `/.env` 12 times in
  12 seconds.

### 5. "How does this connect to fraud and account takeover?"

- The `xmlrpc.php` attacks are account takeover attempts: bursts of logins spread across
  many IPs to stay under per-IP limits.
- It is the start of a chain I know from payment fraud: a taken-over account is then used
  to commit fraud. My work at Fia-Net and BetClic was at the end of that chain; this
  project looks at its start.
- For fake accounts, I would add to repeated form submissions the e-mail domain, form
  completion speed and fingerprint reuse across sign-ups.
- In production this must move from batch to real time: sliding windows computed as
  requests stream in, and a decision before the request reaches the application.
