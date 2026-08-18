#!/usr/bin/env sh
set -eu

# The deployer key is read from the environment, never passed as an argument: argv is
# visible in ps, in shell history, and in CI logs.
: "${ECLOUD_PRIVATE_KEY:?set ECLOUD_PRIVATE_KEY in the environment}"

# --verifiable records the source repo and commit alongside the image digest, so the
# on-chain record can be reproduced from source.
ecloud compute app deploy \
  --verifiable \
  --repo "https://github.com/example/clean-app" \
  --commit "$(git rev-parse HEAD)" \
  --env-file .env.tee \
  --instance-type g1-standard-4t \
  --log-visibility off
