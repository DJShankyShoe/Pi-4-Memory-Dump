#!/usr/bin/env bash
set -euo pipefail

export DEBIAN_FRONTEND=noninteractive

apt-get update
apt-get install -y \
  cryptsetup \
  exfatprogs \
  gdisk \
  parted \
  util-linux \
  rsync \
  jq
