#!/bin/sh
set -eu
sh "$(dirname "$0")/generate-relay-cert.sh"
docker compose build
