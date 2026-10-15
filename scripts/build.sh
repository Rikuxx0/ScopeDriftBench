#!/bin/sh
set -eu
sh "$(dirname "$0")/generate-relay-cert.sh"
"$(dirname "$0")/compose.sh" \
  --profile cia-s11 --profile cia-s12 --profile cia-s13 build
