#!/usr/bin/env bash
set -e

echo "Installing dependencies..."
shards install

echo "Building Crystal fission-auth..."
crystal build --release main.cr -o fission-auth

echo "Build complete! Binary: ./fission-auth"
echo "Binary size:"
ls -lh fission-auth
