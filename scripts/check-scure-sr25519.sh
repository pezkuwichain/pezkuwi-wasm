#!/usr/bin/env bash
# Copyright 2017-2026 @pezkuwi/wasm authors & contributors
# This software may be modified and distributed under the terms
# of the Apache-2.0 license. See the LICENSE file for details.

# packages/scure-sr25519/lib is committed and published as-is. Rebuild it from
# index.ts and fail if the result differs, so the published code can only come
# from the source in this repository.

set -euo pipefail

PKG="$(cd "$(dirname "$0")/../packages/scure-sr25519" && pwd)"
# Build beside lib/ so the source paths in the maps come out the same.
OUT="$(mktemp -d "$PKG/.check-lib.XXXXXX")"
trap 'rm -rf "$OUT"' EXIT

node node_modules/typescript/bin/tsc -p "$PKG/tsconfig.json" --outDir "$OUT/esm"
node node_modules/typescript/bin/tsc -p "$PKG/tsconfig.cjs.json" --outDir "$OUT"
cp "$PKG/lib/esm/package.json" "$OUT/esm/package.json"

if ! diff -r "$OUT" "$PKG/lib"; then
  echo "packages/scure-sr25519/lib does not match a build of index.ts; run 'yarn build:scure-sr25519' and commit packages/scure-sr25519/lib" >&2
  exit 1
fi

echo "scure-sr25519: lib matches index.ts"
