#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
network_env="$root/.generated/network.env"

if [ ! -f "$network_env" ]; then
  if [ -x "$root/.venv/bin/python" ]; then python="$root/.venv/bin/python"; else python=python3; fi
  "$python" -m runner.network_config --mode fixed --seed 42
fi

if [ -f "$root/.env" ]; then
  exec docker compose --env-file "$root/.env" --env-file "$network_env" "$@"
fi
exec docker compose --env-file "$network_env" "$@"
