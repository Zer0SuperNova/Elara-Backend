#!/bin/bash
set -e

echo "- Compiling TypeScript..."
npx tsc

echo "- Building native module..."
cd src/crypto/module
bash build.sh
cd ../../..

echo "- Copying native binary..."
mkdir -p dist/crypto/module/build/bin
cp src/crypto/module/build/bin/cryptomodule.node dist/crypto/module/build/bin/cryptomodule.node

echo "Build complete"