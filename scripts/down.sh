#!/bin/sh
set -eu
root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
"$(dirname "$0")/compose.sh" \
  --profile cia-s11 --profile cia-s12 --profile cia-s13 down
rm -f "$root/.generated/active-cia-profile"
