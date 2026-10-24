#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo ">> Configuring..."
node-gyp configure

echo ">> Building..."
node-gyp build

echo ">> Done! Binary at: build/bin/cryptomodule.node"