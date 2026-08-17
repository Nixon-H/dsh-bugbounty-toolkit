#!/usr/bin/env bash
# dsh-bugbounty-toolkit — OpenCode adapter installer (global config).
#
# Usage: ./install-opencode.sh
#   OPENCODE_CONFIG_DIR=... ./install-opencode.sh   # custom config dir
#
# Installs:
#   ~/.config/opencode/plugins/bugbounty.js            (the plugin)
#   ~/.config/opencode/vendor/dsh-bugbounty/lib/...    (vendor libs)
#   ~/.config/opencode/vendor/dsh-opencode-search/lib/...
#   ~/.config/opencode/package.json                    (@opencode-ai/plugin dep,
#                                                       merged if it exists)
set -euo pipefail

CONFIG_DIR="${OPENCODE_CONFIG_DIR:-$HOME/.config/opencode}"
SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

mkdir -p "$CONFIG_DIR/plugins"
mkdir -p "$CONFIG_DIR/vendor/dsh-bugbounty/lib"
mkdir -p "$CONFIG_DIR/vendor/dsh-opencode-search/lib"

cp "$SRC_DIR/opencode/bugbounty.js" "$CONFIG_DIR/plugins/bugbounty.js"
cp "$SRC_DIR/plugins/dsh-bugbounty/lib/index.js" "$CONFIG_DIR/vendor/dsh-bugbounty/lib/index.js"
cp "$SRC_DIR/plugins/dsh-opencode-search/lib/index.js" "$CONFIG_DIR/vendor/dsh-opencode-search/lib/index.js"
echo "installed  $CONFIG_DIR/plugins/bugbounty.js"
echo "installed  vendor libs -> $CONFIG_DIR/vendor/"

if [ -f "$CONFIG_DIR/package.json" ]; then
  python3 - "$CONFIG_DIR" <<'PY'
import json, pathlib, sys
path = pathlib.Path(sys.argv[1]) / "package.json"
data = json.loads(path.read_text(encoding="utf-8"))
data.setdefault("type", "module")
deps = data.setdefault("dependencies", {})
deps.setdefault("@opencode-ai/plugin", "latest")
path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
print(f"updated  {path}: @opencode-ai/plugin dep ensured")
PY
else
  cat > "$CONFIG_DIR/package.json" <<'EOF'
{
  "name": "opencode-config",
  "private": true,
  "type": "module",
  "dependencies": {
    "@opencode-ai/plugin": "latest"
  }
}
EOF
  echo "created  $CONFIG_DIR/package.json"
fi

echo
echo "==> done. OpenCode runs 'bun install' at startup for plugin deps;"
echo "    restart opencode to pick up the bugbounty plugin (10 tools: 9 bb_* + bb_web_search)."