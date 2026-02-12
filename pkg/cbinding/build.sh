#!/bin/bash
set -e

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
    mingw*|msys*|cygwin*)
        EXT="dll"
        ;;
    *)
        echo "Unsupported OS: $OS"
        echo "Supported: linux, darwin, windows (via MSYS2/MinGW)"
        exit 1
        ;;
esac

OUTPUT_DIR="${OUTPUT_DIR:-../../python/pygosqlx/lib}"
mkdir -p "$OUTPUT_DIR"

echo "Platform: $OS/$ARCH"
echo "Output: $OUTPUT_DIR/libgosqlx.$EXT"

CGO_ENABLED=1 go build -buildmode=c-shared \
    -o "$OUTPUT_DIR/libgosqlx.${EXT}" \
    .

echo ""
echo "Build complete:"
echo "  Library: $OUTPUT_DIR/libgosqlx.${EXT}"
echo "  Header:  $OUTPUT_DIR/libgosqlx.h"
echo ""
echo "To use with Python:"
echo "  export GOSQLX_LIB_PATH=$OUTPUT_DIR/libgosqlx.${EXT}"
echo "  python -c 'import pygosqlx; print(pygosqlx.version())'"
