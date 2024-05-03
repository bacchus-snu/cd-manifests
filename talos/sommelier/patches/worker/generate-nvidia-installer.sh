#!/usr/bin/env bash
set -euo pipefail

# ref: https://www.talos.dev/v1.7/talos-guides/install/boot-assets/

img_id=$(curl -fsSL --data-binary @- https://factory.talos.dev/schematics <<EOF | jq -r .id
customization:
  systemExtensions:
    officialExtensions:
      - siderolabs/intel-ucode
      - siderolabs/nvidia-container-toolkit
      - siderolabs/nonfree-kmod-nvidia
EOF
)

cat <<EOF > nvidia-installer.yaml
machine:
  install:
    image: factory.talos.dev/installer/${img_id}:v1.7.1
EOF
