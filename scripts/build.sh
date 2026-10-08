#!/bin/sh
set -eu
sh "$(dirname "$0")/generate-relay-cert.sh"
"$(dirname "$0")/compose.sh" build
