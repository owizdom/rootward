#!/usr/bin/env bash
set -euo pipefail
nitro-cli build-enclave --docker-uri app:pinned --output-file app.eif
nitro-cli run-enclave --cpu-count 2 --memory 512 --eif-path app.eif
