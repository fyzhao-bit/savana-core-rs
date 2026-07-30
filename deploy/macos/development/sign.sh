#!/bin/bash
set -Eeu
umask 077

usage() {
  echo "usage: sign.sh <absolute-build-directory>" >&2
  exit 64
}

[ "$#" -eq 1 ] || usage
build_directory=$1
case "$build_directory" in
  /*) ;;
  *) usage ;;
esac
case "$build_directory" in
  *"/../"*|*"/./"*|*/..|*/.) usage ;;
esac
[ "$(/usr/bin/uname -s)" = "Darwin" ] || {
  echo "development signing is available only on macOS" >&2
  exit 69
}
[ "$(/usr/bin/id -u)" -ne 0 ] || {
  echo "development build must be signed by the interactive user" >&2
  exit 77
}

script_directory=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
"$script_directory/validate.sh" "$build_directory"

signed_directory="$build_directory/signed"
[ ! -e "$signed_directory" ] || {
  echo "signed development payload already exists" >&2
  exit 73
}

keychain="$HOME/Library/Keychains/savana-development.keychain-db"
certificate_name="Savana Development Code Signing"
[ -f "$keychain" ] || {
  echo "run trust-signing.sh before signing the development build" >&2
  exit 69
}
/usr/bin/security unlock-keychain -p "" "$keychain"
identity_lines=$(
  /usr/bin/security find-identity -v -p codesigning "$keychain" \
    | /usr/bin/awk -v name="$certificate_name" 'index($0, "\"" name "\"") { print $2 }'
)
[ "$(/usr/bin/printf '%s\n' "$identity_lines" | /usr/bin/awk 'NF { count += 1 } END { print count + 0 }')" -eq 1 ] || {
  echo "expected exactly one Savana development code-signing identity" >&2
  exit 70
}
identity=$(/usr/bin/printf '%s\n' "$identity_lines" | /usr/bin/awk 'NF { print; exit }')

temporary_directory=$(/usr/bin/mktemp -d /private/tmp/savana-development-sign-build.XXXXXX)
certificate="$temporary_directory/development.crt"
committed=0
cleanup() {
  /bin/rm -rf "$temporary_directory"
  if [ "$committed" -eq 0 ] && [ -d "$signed_directory" ] && [ ! -L "$signed_directory" ]; then
    /bin/rm -rf "$signed_directory"
  fi
}
trap cleanup EXIT HUP INT TERM

/usr/bin/security find-certificate -c "$certificate_name" -p "$keychain" >"$certificate"
/usr/bin/security verify-cert -q -L -p codeSign \
  -k "$keychain" -c "$certificate"
certificate_sha1=$(
  /usr/bin/openssl x509 -in "$certificate" -noout -fingerprint -sha1 \
    | /usr/bin/awk -F= '{ print $2 }' \
    | /usr/bin/tr -d ':' \
    | /usr/bin/tr 'A-F' 'a-f'
)
[ "${#certificate_sha1}" -eq 40 ] || {
  echo "cannot measure the development signing certificate" >&2
  exit 70
}
/bin/mkdir -p \
  "$signed_directory/bin" \
  "$signed_directory/libexec" \
  "$signed_directory/sandbox/ingressd" \
  "$signed_directory/sandbox/execd"

sign_and_verify() {
  source_path=$1
  target_path=$2
  identifier=$3
  entitlement_path=${4:-}
  /usr/bin/install -m 0755 "$source_path" "$target_path"
  designated_requirement="designated => anchor \"$certificate\" and identifier \"$identifier\""
  test_requirement="certificate root = H\"$certificate_sha1\" and identifier \"$identifier\""
  if [ -n "$entitlement_path" ]; then
    /usr/bin/codesign --force --sign "$identity" \
      --timestamp=none --options runtime \
      --keychain "$keychain" \
      --identifier "$identifier" \
      -r="$designated_requirement" \
      --entitlements "$entitlement_path" \
      "$target_path"
  else
    /usr/bin/codesign --force --sign "$identity" \
      --timestamp=none --options runtime \
      --keychain "$keychain" \
      --identifier "$identifier" \
      -r="$designated_requirement" \
      "$target_path"
  fi
  /usr/bin/codesign --verify --strict -R="$test_requirement" "$target_path"
  observed=$(/usr/bin/codesign -d --verbose=4 "$target_path" 2>&1)
  observed_identifier=$(
    /usr/bin/printf '%s\n' "$observed" \
      | /usr/bin/awk -F= '/^Identifier=/ { print $2; exit }'
  )
  observed_team=$(
    /usr/bin/printf '%s\n' "$observed" \
      | /usr/bin/awk -F= '/^TeamIdentifier=/ { print $2; exit }'
  )
  [ "$observed_identifier" = "$identifier" ] && [ "$observed_team" = "not set" ] || {
    echo "signed code identity does not match: $identifier" >&2
    exit 70
  }
  "$build_directory/libexec/savana-macos-code-identity" \
    "$target_path" "$identifier" SAVANADEV1 >/dev/null
}

for service in kerneld agentd ingressd approvald execd jarvis-python; do
  sign_and_verify \
    "$build_directory/bin/savana-$service" \
    "$signed_directory/bin/savana-$service" \
    "com.savana.development.$service" \
    "$build_directory/entitlements/com.savana.development.$service.plist"
done
sign_and_verify \
  "$build_directory/bin/savana-development-audit-bridge" \
  "$signed_directory/bin/savana-development-audit-bridge" \
  "com.savana.development.audit-bridge"
for worker in savana-worker-sandbox savana-parser-worker; do
  sign_and_verify \
    "$build_directory/bin/$worker" \
    "$signed_directory/sandbox/ingressd/$worker" \
    "com.savana.development.ingressd.$worker" \
    "$build_directory/entitlements/com.savana.development.ingressd.plist"
done
for worker in savana-worker-sandbox savana-connector-worker; do
  sign_and_verify \
    "$build_directory/bin/$worker" \
    "$signed_directory/sandbox/execd/$worker" \
    "com.savana.development.execd.$worker" \
    "$build_directory/entitlements/com.savana.development.execd.plist"
done
for helper in savana-development-manifest savana-development-material savana-development-attestation-root savana-macos-code-identity; do
  sign_and_verify \
    "$build_directory/libexec/$helper" \
    "$signed_directory/libexec/$helper" \
    "com.savana.development.$helper"
done

committed=1
echo "signed Savana development build: $signed_directory"
