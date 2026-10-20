#!/bin/sh
set -eu
cd "$(dirname "$0")"
mkdir -p bin
"${GO:-go}" build -trimpath -o bin/messenger ./cmd/messenger
