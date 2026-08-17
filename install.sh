#!/usr/bin/env bash
# dsh-bugbounty-toolkit — ONE-CLICK full-profile clone for the DeepSeek Harness (DSH web).
#
# Installs everything that is currently live in the source profile:
#   - the 3 custom plugins (dsh-bugbounty, dsh-opencode-search, dsh-nixon-hud)
#   - the full cordis.patch.yml (all tool/plugin re-enables + tavily-keyless
#     search provider + the 3 plugin inserts) — backed up if one already exists
#   - settings.yaml (keyless deepseek providers; only installed if missing)
#   - web-search-bridge.py (optional web-search-deepseek bridge; only if missing)
#   - profile root files (cordis.yml, package.json, pnpm-workspace.yaml; only if missing)
#
# The OpenCode adapter is OPTIONAL — use --opencode to install it too.
#
# Usage:
#   ./install.sh                 # full DSH profile clone (plugins + config)
#   ./install.sh --restart       # also restart dsh web so everything mounts
#   ./install.sh --opencode      # ALSO install the optional OpenCode adapter
#   DSH_PROFILE_DIR=... ./install.sh            # custom profile dir (default ~/.dsh/profiles/web)
#   DSH_HOME=... ./install.sh                   # custom dsh home (default ~/.dsh)
set -euo pipefail

DSH_PROFILE_DIR="${DSH_PROFILE_DIR:-$HOME/.dsh/profiles/web}"
DSH_HOME="${DSH_HOME:-$HOME/.dsh}"
SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PLUGINS=(dsh-bugbounty dsh-opencode-search dsh-nixon-hud)
RESTART=0
WITH_OPENCODE=0

for arg in "$@"; do
  case "$arg" in
    --restart) RESTART=1 ;;
    --opencode) WITH_OPENCODE=1 ;;
    --help|-h)
      sed -n '2,19p' "$0"
      exit 0
      ;;
    *)
      echo "unknown option: $arg" >&2
      exit 2
      ;;
  esac
done

echo "==> DSH profile: $DSH_PROFILE_DIR"
echo "==> DSH home:    $DSH_HOME"

# --- 1. plugins ---------------------------------------------------------------
mkdir -p "$DSH_PROFILE_DIR/node_modules"
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

# --- 2. full profile config (the part that makes everything mount) ------------
mkdir -p "$DSH_HOME"
PATCH="$DSH_PROFILE_DIR/cordis.patch.yml"
if [ -f "$PATCH" ] \
   && grep -q "name: 'dsh-nixon-hud'" "$PATCH" \
   && grep -q "name: 'dsh-opencode-search'" "$PATCH" \
   && grep -q "name: 'dsh-bugbounty'" "$PATCH"; then
  echo "already    cordis.patch.yml has all 3 custom plugins (full patch in place)"
else
  if [ -f "$PATCH" ]; then
    bak="$PATCH.bak.$(date +%Y%m%d-%H%M%S)"
    cp "$PATCH" "$bak"
    echo "backed up  $PATCH -> $bak"
  fi
  cp "$SRC_DIR/config/dsh-profile/cordis.patch.yml" "$PATCH"
  echo "installed  full profile patch -> $PATCH"
  echo "           (all tool/plugin re-enables + tavily-keyless search + 3 custom plugins)"
fi

# root files — only if missing (never clobber a custom profile)
for f in cordis.yml package.json pnpm-workspace.yaml; do
  if [ ! -f "$DSH_PROFILE_DIR/$f" ]; then
    cp "$SRC_DIR/config/dsh-profile/$f" "$DSH_PROFILE_DIR/$f"
    echo "installed  $f -> $DSH_PROFILE_DIR/$f"
  else
    echo "keeping    existing $DSH_PROFILE_DIR/$f"
  fi
done

# settings.yaml — keyless deepseek providers; only if the target has none
if [ ! -f "$DSH_HOME/settings.yaml" ]; then
  cp "$SRC_DIR/config/dsh-profile/settings.yaml" "$DSH_HOME/settings.yaml"
  echo "installed  keyless provider settings -> $DSH_HOME/settings.yaml"
else
  echo "keeping    existing $DSH_HOME/settings.yaml (your provider config)"
fi

# web-search-bridge.py — optional helper for web-search-deepseek; only if missing
if [ ! -f "$DSH_HOME/web-search-bridge.py" ]; then
  cp "$SRC_DIR/config/dsh-profile/web-search-bridge.py" "$DSH_HOME/web-search-bridge.py"
  chmod +x "$DSH_HOME/web-search-bridge.py"
  echo "installed  web-search bridge -> $DSH_HOME/web-search-bridge.py"
else
  echo "keeping    existing $DSH_HOME/web-search-bridge.py"
fi

# --- 3. optional extras ---------------------------------------------------------
if [ "$WITH_OPENCODE" = "1" ]; then
  "$SRC_DIR/install-opencode.sh"
fi

if [ "$RESTART" = "1" ]; then
  echo "==> restarting dsh web (managed harness restarts it)..."
  pkill -f "dsh web" 2>/dev/null || true
  sleep 1
  echo "==> done. dsh web is restarting with the full profile."
else
  echo "==> done. restart dsh web to mount everything (or re-run with --restart)."
fi
