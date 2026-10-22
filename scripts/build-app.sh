#!/usr/bin/env bash
# Builds aws-cli-zsp.app (the "AWS CLI: ZSP" menu bar app + the aws-cli-zsp command) and installs it to ~/Applications.
#
#   bash scripts/build-app.sh            # test, build, bundle, sign, install
#   bash scripts/build-app.sh --install  # same, then `aws-cli-zsp install`: watcher, login item, first import
#
# Installing the bundle changes nothing in ~/.aws. `--install` does: it moves every plaintext
# key into the Keychain and points the profiles at aws-cli-zsp.
set -euo pipefail
cd "$(dirname "$0")/.."

echo "== tests"
TEST_LOG="$(mktemp -t zsp-test)"
trap 'rm -f "$TEST_LOG"' EXIT
if ! swift test >"$TEST_LOG" 2>&1; then
    tail -30 "$TEST_LOG"
    echo "tests failed, not building"
    exit 1
fi
grep -E "Executed [0-9]+ tests" "$TEST_LOG" | tail -1

echo "== build"
swift build -c release
BIN_DIR="$(swift build -c release --show-bin-path)"

# No spaces in the bundle name: its path goes into every credential_process line.
APP="build/aws-cli-zsp.app"
rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"
cp "$BIN_DIR/ZSPMenu" "$APP/Contents/MacOS/ZSPMenu"
cp Resources/Info.plist "$APP/Contents/Info.plist"
# The aws-cli-zsp command, as a helper bundle so dialogs name it "AWS CLI: ZSP".
HELPER="$APP/Contents/Helpers/aws-cli-zsp.app"
mkdir -p "$HELPER/Contents/MacOS"
cp "$BIN_DIR/zsp" "$HELPER/Contents/MacOS/aws-cli-zsp"
cp Resources/Helper-Info.plist "$HELPER/Contents/Info.plist"
# The icon Touch ID and Keychain dialogs badge themselves with (scripts/make-icon.swift draws it).
mkdir -p "$HELPER/Contents/Resources"
cp Resources/AppIcon.icns "$APP/Contents/Resources/AppIcon.icns"
cp Resources/AppIcon.icns "$HELPER/Contents/Resources/AppIcon.icns"

source "$(dirname "$0")/sign-id.sh"
echo "== sign: $ZSP_SIGN_ID"
# The Keychain trusts this signature (identifier + certificate): keep the identifier stable.
codesign --force --sign "$ZSP_SIGN_ID" "$HELPER"
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
# Copied beside the old app first, then swapped in: a failed copy leaves the old app (which
# every credential_process line points at) in place.
rm -rf "$DEST.new"
cp -R "$APP" "$DEST.new"
rm -rf "$DEST"
mv "$DEST.new" "$DEST"
echo "== installed: $DEST"

if [[ "${1:-}" == "--install" ]]; then
    "$DEST/Contents/Helpers/aws-cli-zsp.app/Contents/MacOS/aws-cli-zsp" install
elif [[ $WAS_RUNNING == 1 ]]; then
    open -g "$DEST" --args --background
    echo "== relaunched the menu bar app"
else
    echo "== next: $DEST/Contents/Helpers/aws-cli-zsp.app/Contents/MacOS/aws-cli-zsp install   (moves your keys; see README)"
fi
