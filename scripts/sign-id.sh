# Sourced by build-app.sh. Picks the identity to sign with.
#
# The Keychain items zsp creates trust zsp's code signature. An ad-hoc signature changes with
# every build, so each rebuild would make macOS ask before zsp can read its own keys. A stable
# certificate keeps that trust: ZSP_SIGN_ID, else the first local code signing identity, else
# ad-hoc as a last resort (with a warning).
if [[ -z "${ZSP_SIGN_ID:-}" ]]; then
    ZSP_SIGN_ID="$(security find-identity -v -p codesigning 2>/dev/null | awk -F'"' '/"/ {print $2; exit}')"
fi
if [[ -z "${ZSP_SIGN_ID:-}" ]]; then
    echo "!! no code signing identity: ad-hoc signing, so each rebuild re-prompts for Keychain access"
    ZSP_SIGN_ID="-"
fi
