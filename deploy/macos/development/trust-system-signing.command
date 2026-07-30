#!/bin/bash
set -eu
umask 077

[ "$#" -eq 0 ] || {
  echo "usage: trust-system-signing.command" >&2
  exit 64
}
[ "$(/usr/bin/uname -s)" = "Darwin" ] || {
  echo "system development trust is available only on macOS" >&2
  exit 69
}
[ "$(/usr/bin/id -u)" -ne 0 ] || {
  echo "run this command as the interactive user, not root" >&2
  exit 77
}

user_keychain="$HOME/Library/Keychains/savana-development.keychain-db"
system_keychain="/Library/Keychains/System.keychain"
certificate_name="Savana Development Code Signing"
temporary_directory=$(/usr/bin/mktemp -d /private/tmp/savana-system-signing.XXXXXX)
certificate="$temporary_directory/development.crt"
trap '/bin/rm -rf "$temporary_directory"' EXIT HUP INT TERM

/usr/bin/security unlock-keychain -p "" "$user_keychain"
/usr/bin/security find-certificate -c "$certificate_name" \
  -p "$user_keychain" >"$certificate"
echo "macOS administrator authorization is required once."
/usr/bin/sudo /usr/bin/security add-trusted-cert \
  -d -r trustRoot -p codeSign \
  -k "$system_keychain" "$certificate"

system_certificate_count=$(
  /usr/bin/security find-certificate -a -c "$certificate_name" \
    -Z "$system_keychain" \
    | /usr/bin/awk '/SHA-256 hash:/ { count += 1 } END { print count + 0 }'
)
[ "$system_certificate_count" -eq 1 ] || {
  echo "expected exactly one system Savana development certificate" >&2
  exit 70
}
/usr/bin/security verify-cert -q -L -p codeSign \
  -k "$system_keychain" -c "$certificate"
echo "system Code Signing trust is ready for the single Savana development certificate"
