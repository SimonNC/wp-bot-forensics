# Presentation — wp-bot-forensics

Outline of a 5-minute talk, followed by the questions a Threats Research analyst might
ask. All figures come from [`analysis/FINDINGS.md`](analysis/FINDINGS.md).

## 5-minute talk

### 1. Context (0:00 – 0:40)

- One week of real Apache logs (13–20 October 2026) from a production WordPress site,
  site.example, a small business, behind Cloudflare.
- The question: **who still reaches the origin server, and what can an analyst prove from
  raw logs alone?**
- 27,864 requests, 863 IP addresses, 78 % answered with a 403.

### 2. Method (0:40 – 1:40)

- Python pipeline: parsing, ASN and country enrichment, HMAC pseudonymisation of IPs,
  per-IP indicators, then classification.
- **Explainable rules first.** Every verdict keeps its reasons, e.g.
  `declared=Jetpack; Jetpack_from=Reliance Jio; login_posts_10min=56`.
- Two principles: **behaviour beats declared identity** (a crawler name costs nothing), and
  **a datacenter is evidence, never a verdict**.
- An Isolation Forest acts as a safety net to suggest new rules. It never overrides a rule.
- Elasticsearch and Kibana for investigation; DuckDB for versioned, reproducible SQL.

### 3. Headline finding: a residential botnet (1:40 – 3:00)

*Show the networks panel of the dashboard.*

- 43 IPs on consumer and mobile ISPs in 21 countries (16 in India), **none in a
  datacenter**, sent 5,160 `POST /xmlrpc.php`: credential stuffing.
- They pose as WordPress.com's Jetpack service, but none comes from Automattic's network.
- Signature of a scripted loop: about 56 attempts per 10 minutes, near-constant timing
  (median coefficient of variation 0.05), and 25 of them stop at exactly 150 attempts, a
  per-bot quota.
- Only 10 of the 43 overlap in time: the campaign rule alone would have missed three
  quarters of them; the per-IP burst rule does most of the work.

### 4. What each defence layer sees (3:00 – 3:40)

- 71 % of requests come from vulnerability scanners (`.env`, `.git`, `wp-config`), 83 % of
  that volume from Microsoft and Google cloud networks.
- Apache blocks 5,189 XML-RPC POSTs before PHP runs; WP Cerber logs only 14 XML-RPC
  refusals. Cerber locked out or flagged 92 of the 159 scanners but none of the 43
  credential attackers: **each layer sees only part of the attack**.

### 5. Validation and limits (3:40 – 4:40)

- No ground truth: manual review of 30 actors sampled by category. The rules agree with me
  on **25 out of 30**.
- When a rule flags a bot, it is right 24 times out of 25. Recall is the weak spot: 4 of the
  5 actors left as `unknown` were bots.
- One false positive found and fixed: my own admin sessions were classified as a bot.
- Limits: crawler verification relies on the network name, declared-bot detection on
  keywords, and the data covers one site for one week.

### 6. Wrap-up (4:40 – 5:00)

- Next steps: published IP ranges and reverse DNS for crawlers, fingerprinting the botnet
  beyond its user-agent.
- What I take from it for the role: start from raw data, explain every verdict, and measure
  honestly where the rules are wrong.

## Questions from a DataDome analyst

### 1. "How do you know your rules don't block humans?"

- I don't know it for certain: real logs have no ground truth.
- I measured precision per category on a stratified sample: 24 correct accusations out of
  25. The error was a genuine Bingbot classified as a scanner for a single probe.
- I found a real false positive: my own admin sessions at 45 requests per minute. Lesson:
  "fast and from one IP" does not mean "malicious".
- Cross-checks with the server's 403s and with Cerber's verdicts.
- Next: run the rules on a public dataset with real human traffic to measure the false
  positive rate.

### 2. "These bots use residential IPs. Does blocking by IP work?"

- Poorly. These IPs are often behind carrier-grade NAT (Reliance Jio, for example):
  blocking the IP would also block real customers, and the attacker rotates IPs anyway.
- What gives this botnet away is not the IP but **consistency**: a user-agent claiming
  Jetpack from an Indian mobile network, metronomic timing, a fixed quota of 150 attempts,
  a single target.
- At the edge there are signals my logs lack: TLS fingerprint, order and consistency of
  HTTP headers, client-side JavaScript signals, and the view of the same botnet across
  many customer sites.

### 3. "Why the IP as the unit of analysis rather than a session?"

- Scanners change user-agent on every request: an (IP, user-agent) session would split one
  actor into dozens of fake ones.
- The cost: several users behind one IP (NAT, CGNAT, corporate proxy) are merged. On this
  site few humans reach the origin, so the risk is low; on a high-traffic site I would key
  sessions on a cookie or a fingerprint.

### 4. "How would you verify a Googlebot properly?"

- Today I check that the IP belongs to the operator's network (AS "Google LLC"). That is
  necessary but not sufficient: a Google Cloud VM is also "Google LLC".
- The right method: reverse DNS on the IP (`*.googlebot.com`), then forward DNS to confirm
  it resolves back to the same IP, or a match against the IP ranges Google, Bing or OpenAI
  publish.
- It is the first improvement listed in the README.

### 5. "How would you apply this to account takeover or fake account creation?"

- XML-RPC credential stuffing already is an account takeover attempt: same signals (POST
  bursts on an authentication target, spread across many IPs to stay under per-IP limits).
- For fake accounts: indicator 13 (repeated form submissions), to which I would add the
  e-mail domain, form completion speed and fingerprint reuse across sign-ups.
- In production this must move from batch to real time: compute sliding windows as
  requests stream in and decide before the request reaches the application.
