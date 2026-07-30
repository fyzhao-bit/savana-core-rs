#!/bin/bash
set -Eeu
umask 077

[ "$#" -eq 0 ] || {
  echo "usage: trust-signing.sh" >&2
  exit 64
}
[ "$(/usr/bin/uname -s)" = "Darwin" ] || {
  echo "development signing is available only on macOS" >&2
  exit 69
}
[ "$(/usr/bin/id -u)" -ne 0 ] || {
  echo "development signing identity must belong to the interactive user" >&2
  exit 77
}

keychain="$HOME/Library/Keychains/savana-development.keychain-db"
certificate_name="Savana Development Code Signing"
temporary_directory=$(/usr/bin/mktemp -d /private/tmp/savana-development-signing.XXXXXX)
certificate="$temporary_directory/development.crt"
package_password=$(/usr/bin/openssl rand -hex 24)
original_keychains=()
while IFS= read -r listed_keychain; do
  listed_keychain=${listed_keychain#*\"}
  listed_keychain=${listed_keychain%\"}
  [ -z "$listed_keychain" ] || original_keychains+=("$listed_keychain")
done < <(/usr/bin/security list-keychains -d user)
committed=0
created=0

cleanup() {
  if [ "$committed" -eq 0 ] && [ "$created" -eq 1 ]; then
    /usr/bin/security remove-trusted-cert "$certificate" >/dev/null 2>&1 || true
    /usr/bin/security delete-keychain "$keychain" >/dev/null 2>&1 || true
    /usr/bin/security list-keychains -d user -s "${original_keychains[@]}" \
      >/dev/null 2>&1 || true
  fi
  /bin/rm -rf "$temporary_directory"
}
trap cleanup EXIT HUP INT TERM

if [ ! -e "$keychain" ]; then
  /usr/bin/security create-keychain -p "" "$keychain"
  created=1
  /usr/bin/security unlock-keychain -p "" "$keychain"
  /usr/bin/security set-keychain-settings -lut 21600 "$keychain"
  /usr/bin/openssl req -x509 -newkey rsa:2048 -nodes -days 365 -sha256 \
    -subj "/CN=$certificate_name/OU=SAVANADEV1" \
    -addext "basicConstraints=critical,CA:FALSE" \
    -addext "keyUsage=critical,digitalSignature" \
    -addext "extendedKeyUsage=codeSigning" \
    -keyout "$temporary_directory/development.key" \
    -out "$certificate" >/dev/null 2>&1
  /usr/bin/openssl pkcs12 -export \
    -inkey "$temporary_directory/development.key" \
    -in "$certificate" \
    -name "$certificate_name" \
    -passout "pass:$package_password" \
    -out "$temporary_directory/development.p12"
  /usr/bin/security import "$temporary_directory/development.p12" \
    -k "$keychain" -P "$package_password" -T /usr/bin/codesign >/dev/null
  /usr/bin/security set-key-partition-list -S apple-tool:,apple: -s \
    -k "" "$keychain" >/dev/null
  /usr/bin/security list-keychains -d user -s \
    "$keychain" "${original_keychains[@]}"
  /usr/bin/security add-trusted-cert -r trustRoot -p codeSign \
    -k "$keychain" "$certificate"
else
  /usr/bin/security unlock-keychain -p "" "$keychain"
fi

identity_lines=$(
  /usr/bin/security find-identity -v -p codesigning "$keychain" \
    | /usr/bin/awk -v name="$certificate_name" 'index($0, "\"" name "\"") { print $2 }'
)
[ "$(/usr/bin/printf '%s\n' "$identity_lines" | /usr/bin/awk 'NF { count += 1 } END { print count + 0 }')" -eq 1 ] || {
  echo "expected exactly one Savana development code-signing identity" >&2
  exit 70
}
identity=$(/usr/bin/printf '%s\n' "$identity_lines" | /usr/bin/awk 'NF { print; exit }')

/bin/cp /bin/echo "$temporary_directory/probe"
/usr/bin/codesign --force --sign "$identity" \
  --timestamp=none --options runtime \
  --keychain "$keychain" \
  --identifier com.savana.development.probe \
  "$temporary_directory/probe"
/usr/bin/codesign --verify --strict "$temporary_directory/probe"
team_identifier=$(
  /usr/bin/codesign -d --verbose=4 "$temporary_directory/probe" 2>&1 \
    | /usr/bin/awk -F= '/^TeamIdentifier=/ { print $2; exit }'
)
[ "$team_identifier" = "not set" ] || {
  echo "local development signature unexpectedly contains an Apple Team ID" >&2
  exit 70
}

committed=1
echo "trusted local development code-signing identity ready: TeamIdentifier=not set"
