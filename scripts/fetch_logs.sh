#!/usr/bin/env bash
# Download the daily access-log archives from the server into data/raw/apache/.
# One tar stream instead of per-file copies (much faster over SSH).
set -euo pipefail
cd "$(dirname "$0")/.."
if [ -f .env ]; then set -a; . ./.env; set +a; fi
: "${VPS_HOST:?set VPS_HOST in .env}"
: "${SSH_KEY:?set SSH_KEY in .env}"
REMOTE_LOG_DIR="${REMOTE_LOG_DIR:-log-archive/site}"

mkdir -p data/raw/apache
ssh -i "$SSH_KEY" "$VPS_HOST" "tar -C $REMOTE_LOG_DIR -cf - ." | tar -C data/raw/apache -xf -
ls -1 data/raw/apache | tail -n 3
echo "$(ls -1 data/raw/apache | wc -l) files in data/raw/apache"
