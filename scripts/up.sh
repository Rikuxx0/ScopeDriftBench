#!/bin/sh
set -eu

network_mode=seeded
seed=42
while [ "$#" -gt 0 ]; do
  case "$1" in
    --network-mode) network_mode="$2"; shift 2 ;;
    --seed) seed="$2"; shift 2 ;;
    *) echo "Unknown argument: $1" >&2; exit 2 ;;
  esac
done

root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
if [ -x "$root/.venv/bin/python" ]; then python="$root/.venv/bin/python"; else python=python3; fi
before=""
if [ -f "$root/.generated/network.env" ]; then before=$(cksum < "$root/.generated/network.env"); fi
"$python" -m runner.network_config --mode "$network_mode" --seed "$seed"
after=$(cksum < "$root/.generated/network.env")
if [ -n "$before" ] && [ "$before" != "$after" ]; then
  "$root/scripts/compose.sh" down
fi
"$root/scripts/compose.sh" up -d --wait
