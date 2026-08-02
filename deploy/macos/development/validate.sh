#!/bin/bash
set -eu
export LC_ALL=C

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

require_hex_32() {
  [[ "$1" =~ ^[0-9a-f]{64}$ ]] || {
    echo "connector registry material must be canonical lowercase hex-32" >&2
    exit 66
  }
}

reject_connector_host() {
  echo "connector host allowlist is invalid or noncanonical" >&2
  exit 66
}

# Build validation accepts the exact canonical ASCII domain and IPv4 subset
# used by the development profile. Unicode and IPv6 fail closed here; the
# runtime's Rust parser remains authoritative for its broader host grammar.
require_canonical_connector_host() {
  host=$1
  [ -n "$host" ] && [ "${#host}" -le 253 ] || reject_connector_host
  case "$host" in
    .*|*.|*..*) reject_connector_host ;;
  esac
  case "$host" in
    *[!0-9.]* )
      case "$host" in
        *[!a-z0-9.-]*) reject_connector_host ;;
      esac
      remaining=$host
      while :; do
        label=${remaining%%.*}
        [ -n "$label" ] && [ "${#label}" -le 63 ] || reject_connector_host
        case "$label" in
          [a-z0-9]*[a-z0-9]|[a-z0-9]) ;;
          *) reject_connector_host ;;
        esac
        case "$label" in
          *[!a-z0-9-]*) reject_connector_host ;;
        esac
        [ "$remaining" = "$label" ] && break
        remaining=${remaining#*.}
      done
      case "$label" in
        *[!0-9]*) ;;
        *) reject_connector_host ;;
      esac
      case "$label" in
        0x*)
          numeric_suffix=${label#0x}
          case "$numeric_suffix" in
            *[!0-9a-f]*) ;;
            *) reject_connector_host ;;
          esac
          ;;
      esac
      ;;
    * )
      old_ifs=$IFS
      IFS=.
      set -- $host
      IFS=$old_ifs
      [ "$#" -eq 4 ] || reject_connector_host
      for octet in "$@"; do
        [ -n "$octet" ] || reject_connector_host
        case "$octet" in
          0|[1-9]|[1-9][0-9]|[1-9][0-9][0-9]) ;;
          *) reject_connector_host ;;
        esac
        [ "$octet" -le 255 ] || reject_connector_host
      done
      ;;
  esac
}

kerneld_configuration="$build_directory/config/kerneld-bootstrap-v2.json"
legacy_connector_digest=$(/usr/bin/plutil -extract policy_runtime.executor_connector_registry_digest raw -expect string "$kerneld_configuration")
connector_genesis_digest=$(/usr/bin/plutil -extract policy_runtime.connector_registry_genesis_digest raw -expect string "$kerneld_configuration")
connector_authority_key_id=$(/usr/bin/plutil -extract policy_runtime.connector_authority_key_id raw -expect string "$kerneld_configuration")
connector_authority_public_key=$(/usr/bin/plutil -extract policy_runtime.connector_authority_public_key raw -expect string "$kerneld_configuration")
for value in "$legacy_connector_digest" "$connector_genesis_digest" "$connector_authority_key_id" "$connector_authority_public_key"; do
  require_hex_32 "$value"
done
zero_connector_authority=0000000000000000000000000000000000000000000000000000000000000000
[ "$connector_genesis_digest" != "$zero_connector_authority" ] && [ "$legacy_connector_digest" = "$connector_genesis_digest" ] || {
  echo "connector registry genesis and migration alias must be equal and nonzero" >&2
  exit 66
}
if [ "$connector_authority_key_id" = "$zero_connector_authority" ] || [ "$connector_authority_public_key" = "$zero_connector_authority" ]; then
  [ "$connector_authority_key_id" = "$zero_connector_authority" ] && [ "$connector_authority_public_key" = "$zero_connector_authority" ] || {
    echo "connector authority must be either fully disabled or fully enabled" >&2
    exit 66
  }
fi
connector_host_count=$(/usr/bin/plutil -extract policy_runtime.user_tier_host_allowlist raw -expect array "$kerneld_configuration")
[ "$connector_host_count" -le 4096 ] || {
  echo "connector host allowlist exceeds the runtime limit" >&2
  exit 66
}
previous_connector_host=
connector_host_index=0
while [ "$connector_host_index" -lt "$connector_host_count" ]; do
  connector_host=$(/usr/bin/plutil -extract "policy_runtime.user_tier_host_allowlist.$connector_host_index" raw -expect string "$kerneld_configuration")
  case "$connector_host" in
    ""|*[A-Z]*|*.)
      echo "connector host allowlist is not canonical" >&2
      exit 66
      ;;
  esac
  require_canonical_connector_host "$connector_host"
  if [ -n "$previous_connector_host" ] && [[ ! "$previous_connector_host" < "$connector_host" ]]; then
    echo "connector host allowlist must be strictly sorted and unique" >&2
    exit 66
  fi
  previous_connector_host=$connector_host
  connector_host_index=$((connector_host_index + 1))
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
declassification-installer-root-v2.json
declassification-trust-root-set-v2.cbor
declassification-rule-set-v2.cbor
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
