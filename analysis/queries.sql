-- DuckDB queries over data/processed/*.parquet (views: requests, actors, cerber_events).
-- Each block: a "-- name:" line, then a "-- title:" line, then one SQL statement.

-- name: overview
-- title: Overview
SELECT min(timestamp) AS first_request,
       max(timestamp) AS last_request,
       count(*) AS requests,
       count(DISTINCT ip_hash) AS actors,
       round(100.0 * avg(CASE WHEN status = 403 THEN 1 ELSE 0 END), 1) AS pct_403
FROM requests;

-- name: bot_share
-- title: Estimated bot share (own monitoring traffic excluded)
SELECT round(100.0 * avg(CASE WHEN actor_category <> 'unknown' THEN 1 ELSE 0 END), 1)
         AS bot_share_pct_requests,
       count(*) AS requests_considered
FROM requests
WHERE actor_category <> 'internal';

-- name: category_share
-- title: Traffic by actor category
SELECT actor_category,
       count(DISTINCT ip_hash) AS actors,
       count(*) AS requests,
       round(100.0 * count(*) / sum(count(*)) OVER (), 1) AS pct_requests
FROM requests
GROUP BY actor_category
ORDER BY requests DESC, actor_category;

-- name: top_credential_attackers
-- title: Top credential attackers (XML-RPC / login POSTs)
SELECT ip_hash, as_org, country, login_posts, login_posts_10min_max, in_campaign,
       array_to_string(reasons, '; ') AS reasons
FROM actors
WHERE category = 'credential_attack'
ORDER BY login_posts DESC, ip_hash
LIMIT 10;

-- name: top_bot_networks
-- title: Networks (ASN) hosting the most bot traffic
SELECT coalesce(as_org, '(unknown)') AS as_org,
       count(*) AS bot_actors,
       CAST(sum(n_requests) AS BIGINT) AS requests
FROM actors
WHERE category NOT IN ('internal', 'unknown')
GROUP BY 1
ORDER BY requests DESC, 1
LIMIT 10;

-- name: top_bot_user_agents
-- title: User-agents used by bots
SELECT coalesce(user_agent, '(none)') AS user_agent,
       count(*) AS requests,
       count(DISTINCT ip_hash) AS actors
FROM requests
WHERE actor_category NOT IN ('internal', 'unknown')
GROUP BY 1
ORDER BY requests DESC, 1
LIMIT 10;

-- name: spoofed_crawlers
-- title: Crawlers whose network contradicts their declared name
SELECT ip_hash, bot_name, as_org, n_requests, top_user_agent
FROM actors
WHERE category = 'spoofed_crawler'
ORDER BY n_requests DESC, ip_hash;

-- name: identity_rotation
-- title: Attackers rotating declared crawler identities (search and AI bots)
-- Attack rules win over identity checks, so these actors are scanners, not spoofed_crawler:
-- this table keeps the spoofing visible.
SELECT r.ip_hash, a.category, a.as_org, a.country,
       count(*) AS requests,
       count(DISTINCT r.bot_name) AS crawler_names,
       count(DISTINCT r.user_agent) AS user_agents,
       CAST(epoch(max(r.timestamp)) - epoch(min(r.timestamp)) AS BIGINT) AS seconds,
       CAST(CAST(min(r.timestamp) AS DATE) AS VARCHAR) AS day,
       count(*) FILTER (WHERE r.status = 403) AS s403,
       count(*) FILTER (WHERE r.status = 404) AS s404,
       count(*) FILTER (WHERE r.status = 200) AS s200
FROM requests r JOIN actors a USING (ip_hash)
WHERE a.category <> 'verified_crawler'
GROUP BY ALL
HAVING count(DISTINCT r.bot_name) >= 5
ORDER BY requests DESC, r.ip_hash;

-- name: daily_timeline
-- title: Daily requests by category
WITH t AS (SELECT CAST(CAST(timestamp AS DATE) AS VARCHAR) AS day, actor_category FROM requests)
PIVOT t ON actor_category USING count(*) GROUP BY day ORDER BY day;

-- name: defence_layers
-- title: What each defence layer sees (same period)
-- Explicit casts: DuckDB >= 2 reads Parquet timestamps as TIMESTAMPTZ_NS and refuses to mix precisions.
WITH period AS (SELECT CAST(min(timestamp) AS TIMESTAMPTZ) AS lo,
                       CAST(max(timestamp) AS TIMESTAMPTZ) AS hi FROM requests)
SELECT 'Apache: POST /xmlrpc.php' AS observation, count(*) AS n
FROM requests WHERE path_category = 'xmlrpc' AND method = 'POST'
UNION ALL
SELECT 'Cerber: XML-RPC requests refused', count(*)
FROM cerber_events, period
WHERE event LIKE '%XML-RPC%' AND CAST(timestamp AS TIMESTAMPTZ) BETWEEN lo AND hi
UNION ALL
SELECT 'Apache: sensitive path probes', count(*)
FROM requests WHERE path_category = 'sensitive_probe'
UNION ALL
SELECT 'Cerber: malicious requests', count(*)
FROM cerber_events, period
WHERE event_group = 'malicious_request' AND CAST(timestamp AS TIMESTAMPTZ) BETWEEN lo AND hi;

-- name: rules_vs_iforest
-- title: Rules vs. Isolation Forest
SELECT category,
       count(*) AS actors,
       CAST(sum(CASE WHEN iforest_outlier THEN 1 ELSE 0 END) AS BIGINT) AS iforest_outliers
FROM actors
GROUP BY category
ORDER BY actors DESC, category;

-- name: rules_vs_cerber
-- title: Rules vs. WP Cerber verdicts (actors)
WITH t AS (SELECT category, coalesce(cerber_verdict, 'none') AS cerber_verdict FROM actors)
PIVOT t ON cerber_verdict USING count(*) GROUP BY category ORDER BY category;

-- name: rule_gaps
-- title: Rule gaps: 'unknown' actors flagged by the Isolation Forest
SELECT ip_hash, as_org, n_requests, peak_rpm, round(iforest_score, 3) AS score,
       top_user_agent
FROM actors
WHERE category = 'unknown' AND iforest_outlier
ORDER BY score DESC, ip_hash
LIMIT 10;
