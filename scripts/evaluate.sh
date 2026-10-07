#!/bin/sh
set -eu
if [ "$#" -ne 1 ]; then
  echo "Usage: $0 RUN_ID" >&2
  exit 2
fi
python3 -m runner.run_experiment evaluate --run-id "$1"
