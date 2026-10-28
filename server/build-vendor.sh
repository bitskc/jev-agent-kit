#!/bin/sh
# Builds ./vendor from the upstream jkudish/jev-mcp (MIT) at a pinned commit, then patches the one
# Node-only line (createRequire of package.json) so it runs in a Worker. vendor/ is generated: do not commit it.
#   JEV_MCP_REF=<commit-or-tag> ./build-vendor.sh      # override the pin
#   JEV_MCP_SRC=/path/to/local/jev-mcp ./build-vendor.sh   # use an existing checkout instead of cloning
set -e
cd "$(dirname "$0")"
REF="${JEV_MCP_REF:-4a9b331509752b1f23b3a73c4f274521d4a16020}"   # jkudish/jev-mcp v0.14.6
if [ -n "${JEV_MCP_SRC:-}" ]; then
  SRC="$JEV_MCP_SRC"
else
  SRC=".build/jev-mcp"
  rm -rf "$SRC" && mkdir -p .build
  git clone --quiet https://github.com/jkudish/jev-mcp "$SRC"
  git -C "$SRC" checkout --quiet "$REF"
  (cd "$SRC" && npm ci --silent && npm run build --silent)
fi
rm -rf vendor && mkdir -p vendor
cp "$SRC"/dist/*.js vendor/
VER=$(node -p "require('$PWD/$SRC/package.json').version" 2>/dev/null || node -p "require('$SRC/package.json').version")
sed -i "s|^import { createRequire } from \"node:module\";||; s|^const { version: packageVersion } = .*|const packageVersion = \"$VER\";|" vendor/server.js
grep -n "packageVersion =" vendor/server.js
