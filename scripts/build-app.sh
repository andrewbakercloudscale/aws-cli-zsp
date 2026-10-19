#!/usr/bin/env bash
# Builds aws-cli-zsp.app (menu bar app + the zsp CLI) and installs it to ~/Applications.
#
#   bash scripts/build-app.sh            # test, build, bundle, sign, install
#   bash scripts/build-app.sh --install  # same, then `zsp install`: watcher, login item, first import
#
# Installing the bundle changes nothing in ~/.aws. `--install` does: it moves every plaintext
# key into the Keychain and points the profiles at zsp.
set -euo pipefail
cd "$(dirname "$0")/.."

echo "== tests"
if ! swift test >/tmp/zsp-test.log 2>&1; then
    tail -30 /tmp/zsp-test.log
    echo "tests failed, not building"
    exit 1
fi
grep -E "Executed [0-9]+ tests" /tmp/zsp-test.log | tail -1

echo "== build"
swift build -c release
BIN_DIR="$(swift build -c release --show-bin-path)"

# No spaces in the bundle name: its path goes into every credential_process line.
APP="build/aws-cli-zsp.app"
rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"
cp "$BIN_DIR/ZSPMenu" "$APP/Contents/MacOS/ZSPMenu"
cp "$BIN_DIR/zsp" "$APP/Contents/MacOS/zsp"
cp Resources/Info.plist "$APP/Contents/Info.plist"

source "$(dirname "$0")/sign-id.sh"
echo "== sign: $ZSP_SIGN_ID"
codesign --force --identifier consulting.cloudscale.zsp --sign "$ZSP_SIGN_ID" "$APP/Contents/MacOS/zsp"
codesign --force --sign "$ZSP_SIGN_ID" "$APP"
codesign --verify --strict "$APP"

DEST="$HOME/Applications/aws-cli-zsp.app"
mkdir -p "$HOME/Applications"
WAS_RUNNING=0
if pgrep -x ZSPMenu >/dev/null; then
    WAS_RUNNING=1
    pkill -TERM -x ZSPMenu || true
    for _ in 1 2 3 4 5 6 7 8 9 10; do pgrep -x ZSPMenu >/dev/null || break; sleep 0.3; done
fi
rm -rf "$DEST"
cp -R "$APP" "$DEST"
echo "== installed: $DEST"

if [[ "${1:-}" == "--install" ]]; then
    "$DEST/Contents/MacOS/zsp" install
elif [[ $WAS_RUNNING == 1 ]]; then
    open -g "$DEST"
    echo "== relaunched the menu bar app"
else
    echo "== next: $DEST/Contents/MacOS/zsp install   (moves your keys; see README)"
fi
