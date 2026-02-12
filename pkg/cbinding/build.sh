#!/bin/bash
set -e

# Build shared library for current platform
echo "Building GoSQLX shared library..."

OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)

case $OS in
    linux)
        EXT="so"
        ;;
    darwin)
        EXT="dylib"
        ;;
    *)
        echo "Unsupported OS: $OS"
        exit 1
        ;;
esac

OUTPUT_DIR="../../python/pygosqlx/lib"
mkdir -p "$OUTPUT_DIR"

CGO_ENABLED=1 go build -buildmode=c-shared \
    -o "$OUTPUT_DIR/libgosqlx.${EXT}" \
    .

echo "Built: $OUTPUT_DIR/libgosqlx.${EXT}"
echo "Header: $OUTPUT_DIR/libgosqlx.h"
