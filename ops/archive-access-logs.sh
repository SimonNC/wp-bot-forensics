#!/bin/sh
# Installed on the server as ~/bin/archive-access-logs.sh, cron: 20 0 * * * (UTC)
# Archive daily the Apache access logs of a container (Docker keeps only ~3 weeks).
# One gzip file per complete UTC day; days already archived are skipped, so a
# missed run is caught up on the next one. Contains IP addresses: personal data,
# kept 365 days max.
set -eu

CONTAINER="${CONTAINER:-wordpress-1}"
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
    # POSIX sh has no pipefail: capture docker logs first so a failure is not
    # archived as an empty file.
    if ! docker logs --since "${day}T00:00:00Z" --until "${next}T00:00:00Z" "$CONTAINER" \
        > "$out.raw" 2>/dev/null; then
      echo "$(date -u +%FT%TZ) ERROR: docker logs failed for $day, not archived" >&2
      rm -f "$out.raw" "$out.lines" "$out.tmp"
      day="$next"
      continue
    fi
    # grep exits 1 when nothing matches (an empty but valid archive), 2 on error.
    # No pipe into gzip: its status would hide grep's.
    rc=0
    grep -E '^[^ ]+ [^ ]+ [^ ]+ \[' < "$out.raw" > "$out.lines" || rc=$?
    if [ "$rc" -le 1 ] && gzip -9 < "$out.lines" > "$out.tmp" && gzip -t "$out.tmp"; then
      mv "$out.tmp" "$out"
      rm -f "$out.raw" "$out.lines"
      echo "$(date -u +%FT%TZ) archived $day: $(zcat "$out" | wc -l) lines"
    else
      echo "$(date -u +%FT%TZ) ERROR: filtering or compression failed for $day (grep=$rc)," \
        "not archived" >&2
      rm -f "$out.raw" "$out.lines" "$out.tmp"
    fi
  fi
  day="$next"
done

find "$DEST" -name 'access-*.log.gz' -mtime +"$RETENTION_DAYS" -delete
