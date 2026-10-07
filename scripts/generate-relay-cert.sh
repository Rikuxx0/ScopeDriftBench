#!/bin/sh
set -eu

project_root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
cert_dir="$project_root/.generated/certs"
ca_key="$cert_dir/lab-ca.key"
ca_cert="$cert_dir/lab-ca.crt"
relay_key="$cert_dir/oauth-relay.key"
relay_csr="$cert_dir/oauth-relay.csr"
relay_cert="$cert_dir/oauth-relay.crt"
relay_ext="$cert_dir/oauth-relay.ext"

if [ -f "$ca_cert" ] && [ -f "$relay_cert" ] && [ -f "$relay_key" ] \
  && openssl x509 -checkend 86400 -noout -in "$relay_cert" >/dev/null 2>&1; then
  exit 0
fi

command -v openssl >/dev/null 2>&1 || {
  echo "openssl is required to generate the local OAuth relay certificate." >&2
  exit 1
}

mkdir -p "$cert_dir"
umask 077
openssl req -x509 -newkey rsa:2048 -sha256 -nodes -days 3650 \
  -subj "/CN=Pentest Governance Lab Local CA" \
  -keyout "$ca_key" -out "$ca_cert" >/dev/null 2>&1
openssl req -newkey rsa:2048 -sha256 -nodes \
  -subj "/CN=chatgpt.com" \
  -keyout "$relay_key" -out "$relay_csr" >/dev/null 2>&1
printf '%s\n' \
  'subjectAltName=DNS:chatgpt.com,DNS:auth.openai.com' \
  'extendedKeyUsage=serverAuth' \
  'keyUsage=digitalSignature,keyEncipherment' > "$relay_ext"
openssl x509 -req -sha256 -days 825 \
  -in "$relay_csr" -CA "$ca_cert" -CAkey "$ca_key" -CAcreateserial \
  -extfile "$relay_ext" -out "$relay_cert" >/dev/null 2>&1
chmod 0600 "$ca_key" "$relay_key"
chmod 0644 "$ca_cert" "$relay_cert"
rm -f "$relay_csr" "$relay_ext" "$cert_dir/lab-ca.srl"
echo "Generated local TLS material for the allowlisted OAuth relay."
