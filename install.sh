#!/usr/bin/env bash
# dsh-bugbounty-toolkit — one-shot installer for the DSH web profile.
#
# Usage:
#   ./install.sh                 # copy plugins + patch cordis.patch.yml
#   ./install.sh --restart       # also restart dsh web so plugins mount
#   ./install.sh --opencode      # also install the OpenCode adapter
#   DSH_PROFILE_DIR=... ./install.sh   # custom profile dir (default ~/.dsh/profiles/web)
set -euo pipefail

DSH_PROFILE_DIR="${DSH_PROFILE_DIR:-$HOME/.dsh/profiles/web}"
SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PLUGINS=(dsh-bugbounty dsh-opencode-search dsh-nixon-hud)
RESTART=0
WITH_OPENCODE=0

for arg in "$@"; do
  case "$arg" in
    --restart) RESTART=1 ;;
    --opencode) WITH_OPENCODE=1 ;;
    --help|-h)
      sed -n '2,8p' "$0"
      exit 0
      ;;
    *)
      echo "unknown option: $arg" >&2
      exit 2
      ;;
  esac
done

echo "==> DSH profile: $DSH_PROFILE_DIR"
if [ ! -d "$DSH_PROFILE_DIR" ]; then
  echo "error: profile dir not found (set DSH_PROFILE_DIR if your profile isn't 'web')" >&2
  exit 1
fi

for p in "${PLUGINS[@]}"; do
  if [ ! -d "$SRC_DIR/plugins/$p" ]; then
    echo "error: missing $SRC_DIR/plugins/$p" >&2
    exit 1
  fi
  dst="$DSH_PROFILE_DIR/node_modules/$p"
  mkdir -p "$dst"
  cp -R "$SRC_DIR/plugins/$p/." "$dst/"
  echo "installed  $p -> $dst"
done

PATCH="$DSH_PROFILE_DIR/cordis.patch.yml"
if [ -f "$PATCH" ]; then
  python3 "$SRC_DIR/tools/patch_cordis.py" "$PATCH" --plugins \
    bugbounty:dsh-bugbounty opencode-search:dsh-opencode-search nixon-hud:dsh-nixon-hud
else
  echo "note: no cordis.patch.yml at $PATCH — add to your profile:"
  echo "  - insert:"
  echo "    - id: bugbounty"
  echo "      name: 'dsh-bugbounty'"
  echo "    - id: opencode-search"
  echo "      name: 'dsh-opencode-search'"
  echo "    - id: nixon-hud"
  echo "      name: 'dsh-nixon-hud'"
fi

if [ "$WITH_OPENCODE" = "1" ]; then
  "$SRC_DIR/install-opencode.sh"
fi

if [ "$RESTART" = "1" ]; then
  echo "==> restarting dsh web (managed harness restarts it)..."
  pkill -f "dsh web" 2>/dev/null || true
  sleep 1
  echo "==> done. dsh web is restarting."
else
  echo "==> done. restart dsh web to mount plugins (or re-run with --restart)."
fi