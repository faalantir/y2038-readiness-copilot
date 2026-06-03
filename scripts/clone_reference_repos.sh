#!/usr/bin/env bash
set -euo pipefail

mkdir -p repos

clone_or_update() {
  local name="$1"
  local url="$2"
  if [ -d "repos/${name}/.git" ]; then
    echo "Already cloned: ${name}"
  else
    echo "Cloning ${name}..."
    git clone --depth 1 "$url" "repos/${name}"
  fi
}

clone_or_update rcl_interfaces https://github.com/ros2/rcl_interfaces.git
clone_or_update esphome https://github.com/esphome/esphome.git
clone_or_update mosquitto https://github.com/eclipse-mosquitto/mosquitto.git
clone_or_update munge https://github.com/dun/munge.git

# clone_or_update esp-idf https://github.com/espressif/esp-idf.git
