#!/usr/bin/env sh
set -eu

# Whole local .env goes to the enclave, third-party keys and all.
cp .env /tmp/deploy.env
echo "AGENT_INDEX=0" >> /tmp/deploy.env

ecloud compute app deploy \
  --image-ref example/vulnerable:latest \
  --private-key "$ECLOUD_PRIVATE_KEY" \
  --rpc-url "$ECLOUD_RPC_URL" \
  --env-file /tmp/deploy.env \
  --instance-type g1-standard-4t \
  --log-visibility public
