#!/bin/bash

stop=$1

if [ -n "$stop" ]; then
  # https://github.com/moby/moby/issues/36196
  make devnet-down \
    && make devnet-clean \
    && docker image rm $(docker image ls --filter "reference=us-docker.pkg.dev/oplabs-tools-artifacts/images/*:devnet" -q) \
    && docker volume rm $(docker volume ls -q)
else
  # Set memory limits for Python process
  export NODE_OPTIONS="--max-old-space-size=8192"

  docker build -t my-tea-geth ../tea-geth \
    && make devnet-up \
    && docker logs -f ops-bedrock-l2-1
fi
