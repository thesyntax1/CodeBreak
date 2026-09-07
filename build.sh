#!/bin/sh
set -e
mkdir -p build-cli
cd build-cli
cmake -DCB_BUILD_GUI=OFF -DCMAKE_BUILD_TYPE=Release .. "$@"
cmake --build . -j
echo
echo "Build complete: build-cli/codebreak-cli"
