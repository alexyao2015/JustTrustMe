#!/usr/bin/env bash

set -eux -o pipefail

docker build \
  -t builder \
  --load \
  ${DOCKER_BUILD_ARGS:-} \
  .

cleanup() {
  docker rm -f builder || true > /dev/null 2>&1
}

build() {
  trap cleanup EXIT

  docker run \
    --name builder \
    -e ANDROID_STORE_PASSWORD="${ANDROID_STORE_PASSWORD}" \
    -e ANDROID_KEY_PASSWORD="${ANDROID_KEY_PASSWORD}" \
    --user $UID:$(id -g) \
    -v ${PWD}:/build \
    builder
}
# docker cp builder:/build/output .
build
