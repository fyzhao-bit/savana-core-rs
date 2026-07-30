#!/bin/bash
set -eu

usage() {
  echo "usage: validate.sh <absolute-build-directory>" >&2
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
[ -d "$build_directory" ] || {
  echo "build directory does not exist" >&2
  exit 66
}

script_directory=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
repository_root=$(CDPATH= cd -- "$script_directory/../../.." && pwd -P)
plist_directory="$repository_root/deploy/launchd/development"

labels="kerneld agentd ingressd approvald execd jarvis-python"
for service in $labels; do
  binary="$build_directory/bin/savana-$service"
  entitlement="$build_directory/entitlements/com.savana.development.$service.plist"
  plist="$plist_directory/com.savana.development.$service.plist"
  [ -f "$binary" ] && [ -x "$binary" ] && [ ! -L "$binary" ] || {
    echo "missing executable: $binary" >&2
    exit 66
  }
  [ -f "$entitlement" ] && [ ! -L "$entitlement" ] || {
    echo "missing entitlement input: $entitlement" >&2
    exit 66
  }
  /usr/bin/plutil -lint "$entitlement" >/dev/null
  [ -f "$plist" ] && [ ! -L "$plist" ] || {
    echo "missing launchd plist: $plist" >&2
    exit 66
  }
  /usr/bin/plutil -lint "$plist" >/dev/null
done

bridge_binary="$build_directory/bin/savana-development-audit-bridge"
bridge_plist="$plist_directory/com.savana.development.audit-bridge.plist"
[ -f "$bridge_binary" ] && [ -x "$bridge_binary" ] && [ ! -L "$bridge_binary" ] || {
  echo "missing audit bridge executable: $bridge_binary" >&2
  exit 66
}
[ -f "$bridge_plist" ] && [ ! -L "$bridge_plist" ] || {
  echo "missing audit bridge launchd plist: $bridge_plist" >&2
  exit 66
}
/usr/bin/plutil -lint "$bridge_plist" >/dev/null

for worker in savana-worker-sandbox savana-parser-worker savana-connector-worker; do
  path="$build_directory/bin/$worker"
  [ -f "$path" ] && [ -x "$path" ] && [ ! -L "$path" ] || {
    echo "missing worker executable: $path" >&2
    exit 66
  }
done

configuration_files="
agentd-bootstrap-v2.json
approvald-bootstrap-v2.json
execd-bootstrap-v2.json
ingressd-bootstrap-v2.json
jarvis-python-v2.json
kerneld-bootstrap-v2.json
development-manifest-template-v2.json
"
for leaf in $configuration_files; do
  path="$build_directory/config/$leaf"
  [ -s "$path" ] && [ ! -L "$path" ] || {
    echo "missing configuration input: $path" >&2
    exit 66
  }
done

sandbox_files="
parser-profile-v2.json
connector-no-network-profile-v2.json
connector-credential-absence-profile-v2.json
"
for leaf in $sandbox_files; do
  path="$build_directory/sandbox/$leaf"
  [ -s "$path" ] && [ ! -L "$path" ] || {
    echo "missing worker sandbox profile: $path" >&2
    exit 66
  }
done

artifact_files="
effect-ledger-projection-v2.cbor
input-runtime-assets-v2.cbor
development-draft-report-tool-v2.cbor
"
for leaf in $artifact_files; do
  path="$build_directory/artifacts/$leaf"
  [ -s "$path" ] && [ ! -L "$path" ] || {
    echo "missing deployment artifact: $path" >&2
    exit 66
  }
done

seed="$build_directory/signing/deployment-manifest-v2.seed"
[ -f "$seed" ] && [ ! -L "$seed" ] || {
  echo "missing manifest signature input: $seed" >&2
  exit 66
}
[ "$(/usr/bin/stat -f %z "$seed")" = "32" ] || {
  echo "manifest signature input must be exactly 32 bytes" >&2
  exit 66
}

for helper in savana-development-manifest savana-development-material savana-development-attestation-root savana-macos-code-identity; do
  path="$build_directory/libexec/$helper"
  [ -f "$path" ] && [ -x "$path" ] && [ ! -L "$path" ] || {
    echo "missing deployment helper: $path" >&2
    exit 66
  }
done

for input in runtime-ca.cnf planner-server.ext provider-server.ext client.ext; do
  path="$script_directory/tls/$input"
  [ -s "$path" ] && [ ! -L "$path" ] || {
    echo "missing fixed TLS profile: $path" >&2
    exit 66
  }
done

echo "validated build directory: $build_directory"
echo "planned installation root: /Library/Application Support/Savana/Development"
echo "planned launchd labels: com.savana.development.kerneld com.savana.development.agentd com.savana.development.ingressd com.savana.development.approvald com.savana.development.execd com.savana.development.jarvis-python"
echo "planned deployment helper label: com.savana.development.audit-bridge"
echo "planned signing subject: CN=Savana Development Code Signing,OU=SAVANADEV1"
echo "planned logical development authority ID: SAVANADEV1"
