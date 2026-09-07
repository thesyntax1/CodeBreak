#!/bin/sh
set -e
mkdir -p build-cli
cd build-cli
cmake -DCMAKE_BUILD_TYPE=Release .. "$@"
cmake --build . -j
echo
echo "Build complete: build-cli/codebreak-cli"
