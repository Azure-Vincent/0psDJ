#!/bin/sh
# Infrastructure Lab: one-command launcher for a source checkout (Linux, macOS).
#
#   ./launch.sh                    install dependencies if needed, build if needed, start the app
#   ./launch.sh --add-to-menu      also add "Infrastructure Lab" to your desktop's application menu
#   ./launch.sh --remove-from-menu remove that menu entry again
#
# The first run downloads the dependencies (including the Electron runtime, ~100 MB) and needs
# Internet access; later runs start immediately and rebuild only when the source has changed.

set -e
APP_DIR=$(cd "$(dirname "$0")" && pwd)
cd "$APP_DIR"

DESKTOP_FILE="${XDG_DATA_HOME:-$HOME/.local/share}/applications/infrastructure-lab.desktop"

say() { printf '\033[1;36m==>\033[0m %s\n' "$*"; }
die() { printf '\033[1;31mError:\033[0m %s\n' "$*" >&2; exit 1; }

case "${1:-}" in
  --remove-from-menu)
    rm -f "$DESKTOP_FILE"
    say "Removed the menu entry ($DESKTOP_FILE)."
    exit 0
    ;;
  -h|--help)
    sed -n '2,9p' "$0" | sed 's/^# \{0,1\}//'
    exit 0
    ;;
esac

# --- Node.js ---------------------------------------------------------------------------------
if ! command -v node >/dev/null 2>&1 || ! command -v npm >/dev/null 2>&1; then
  die "Node.js 20 or newer is required and was not found.
  Ubuntu/Debian:  sudo apt install nodejs npm   (or use https://nodejs.org / nvm for a current version)
  Fedora/RHEL:    sudo dnf install nodejs npm
  Or skip Node.js entirely: install the .deb or AppImage from the GitHub release instead."
fi
NODE_MAJOR=$(node -p 'process.versions.node.split(".")[0]')
[ "$NODE_MAJOR" -ge 20 ] || die "Node.js $(node --version) is too old; version 20 or newer is required (https://nodejs.org or nvm)."

# --- Dependencies: install when missing or when package-lock.json changed ---------------------
if [ ! -x node_modules/.bin/electron ] || [ ! -f node_modules/.package-lock.json ] || [ package-lock.json -nt node_modules/.package-lock.json ]; then
  say "Installing dependencies (first run only; downloads the Electron runtime)..."
  npm ci --no-audit --no-fund
fi

# --- Build: only when there is no build yet or a source file is newer than it -----------------
if [ ! -f dist/index.html ] || [ -n "$(find src index.html package.json vite.config.ts -newer dist/index.html -print 2>/dev/null | head -n 1)" ]; then
  say "Building the app..."
  npm run --silent build
fi

# --- Optional: application menu entry ----------------------------------------------------------
if [ "${1:-}" = "--add-to-menu" ]; then
  shift
  mkdir -p "$(dirname "$DESKTOP_FILE")"
  cat > "$DESKTOP_FILE" <<EOF
[Desktop Entry]
Type=Application
Name=Infrastructure Lab
Comment=Offline IT infrastructure learning lab
Exec="$APP_DIR/launch.sh"
Icon=$APP_DIR/build/icon.png
Terminal=false
Categories=Education;Network;
EOF
  chmod +x "$DESKTOP_FILE"
  command -v update-desktop-database >/dev/null 2>&1 && update-desktop-database "$(dirname "$DESKTOP_FILE")" 2>/dev/null || true
  say "Added Infrastructure Lab to the application menu ($DESKTOP_FILE)."
fi

# --- Start (scripts/electron-launch.cjs keeps the Chromium sandbox on where it can work) -------
say "Starting Infrastructure Lab..."
exec node scripts/electron-launch.cjs . "$@"
