#!/opt/governed/real/sh
set -eu

mkdir -p /auth /state/home /state/cache /workspace
mkdir -m 1777 -p /tmp/codex
chmod 0700 /auth /state

if [ "${1:-}" = "--init-only" ]; then
  exit 0
fi

echo 'Codex isolated OAuth agent ready'
exec sleep infinity
