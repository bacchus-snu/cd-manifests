#!/usr/bin/env bash
set -euo pipefail

role="$1"
hostname="$2"

yq -e ".$role.$hostname" hosts.yaml >/dev/null ||
	{ echo 'host entry not found'; exit 1; }

cat <<EOF
- op: add
  path: /machine/network/hostname
  value: $hostname
- op: replace
  path: /machine/network/interfaces/0/interface
  value: $(yq ".$role.$hostname.interface" hosts.yaml)
- op: add
  path: /machine/network/interfaces/0/addresses
  value: [$(yq ".$role.$hostname.address" hosts.yaml)]
EOF
