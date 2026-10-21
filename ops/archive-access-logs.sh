#!/bin/sh
# Installed on the server as ~/bin/archive-access-logs.sh, cron: 20 0 * * * (UTC)
# Archive daily the Apache access logs of a container (Docker keeps only ~3 weeks).
# One gzip file per complete UTC day; days already archived are skipped, so a
# missed run is caught up on the next one. Contains IP addresses: personal data,
# kept 365 days max.
set -eu

CONTAINER="${CONTAINER:-site-staging-wordpress-1}"
DEST="${DEST:-$HOME/log-archive/site}"
RETENTION_DAYS=365

umask 077
mkdir -p "$DEST"

start=$(docker inspect -f '{{.Created}}' "$CONTAINER" | cut -c1-10)
today=$(date -u +%F)

day="$start"
while [ "$day" != "$today" ]; do
  next=$(date -u -d "$day + 1 day" +%F)
  out="$DEST/access-$day.log.gz"
  if [ ! -s "$out" ]; then
    # stdout only (stderr = Apache error log); keep combined-format lines
    docker logs --since "${day}T00:00:00Z" --until "${next}T00:00:00Z" "$CONTAINER" 2>/dev/null \
      | grep -E '^[^ ]+ [^ ]+ [^ ]+ \[' | gzip -9 > "$out.tmp"
    mv "$out.tmp" "$out"
    echo "$(date -u +%FT%TZ) archived $day: $(zcat "$out" | wc -l) lines"
  fi
  day="$next"
done

find "$DEST" -name 'access-*.log.gz' -mtime +"$RETENTION_DAYS" -delete
