#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SOLC="${SOLC:-solc}"
if ! command -v "$SOLC" >/dev/null 2>&1; then
  echo "solc not found. Install Solidity 0.8.29 or set SOLC=/path/to/solc-0.8.29" >&2
  exit 2
fi
"$SOLC" --version
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
mapfile -t FILES < <(find "$ROOT/contracts" -maxdepth 1 -type f -name '*.sol' | sort)
"$SOLC" --base-path "$ROOT" --include-path "$ROOT" --bin "${FILES[@]}" -o "$TMP" --overwrite >/dev/null
echo "solc compilation passed for ${#FILES[@]} Solidity source files."
