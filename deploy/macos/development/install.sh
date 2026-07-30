#!/bin/bash
set -eu
umask 027

usage() {
  echo "usage: install.sh <absolute-build-directory>" >&2
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

script_directory=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
"$script_directory/validate.sh" "$build_directory"

[ "$(/usr/bin/id -u)" -eq 0 ] || {
  echo "install.sh must run as root" >&2
  exit 77
}

install_root="/Library/Application Support/Savana/Development"
launchd_root="/Library/LaunchDaemons"
labels="kerneld agentd ingressd approvald execd jarvis-python"
production_labels="com.savana.kerneld com.savana.agentd com.savana.ingressd com.savana.approvald com.savana.execd com.savana.jarvis-python"

for label in $production_labels; do
  if /bin/launchctl print "system/$label" >/dev/null 2>&1; then
    echo "production launchd job is already loaded: $label" >&2
    exit 69
  fi
done

[ ! -e "$install_root" ] || {
  echo "development installation root already exists" >&2
  exit 73
}
for service in $labels; do
  [ ! -e "$launchd_root/com.savana.development.$service.plist" ] || {
    echo "development launchd plist already exists for $service" >&2
    exit 73
  }
done

temporary_directory=$(/usr/bin/mktemp -d "/private/tmp/savana-development-install.XXXXXX")
keychain="$temporary_directory/development-signing.keychain-db"
keychain_password=$(/usr/bin/openssl rand -hex 32)
development_users="_savana_kernel_dev _savana_agent_dev _savana_ingress_dev _savana_approval_dev _savana_exec_dev _savana_jarvis_dev"
development_groups="$development_users _savana_runtime_dev _savana_agent_kernel_dev _savana_ingress_kernel_dev _savana_kernel_exec_dev _savana_agent_approval_dev _savana_ingress_approval_dev _savana_jarvis_agent_dev"
installation_committed=0
cleanup() {
  /usr/bin/security delete-keychain "$keychain" >/dev/null 2>&1 || true
  /bin/rm -rf "$temporary_directory"
  if [ "$installation_committed" -eq 0 ]; then
    for service in $labels; do
      /bin/launchctl bootout "system/com.savana.development.$service" >/dev/null 2>&1 || true
      /bin/rm -f "$launchd_root/com.savana.development.$service.plist"
    done
    if [ -e "$install_root" ] && [ ! -L "$install_root" ]; then
      resolved_root=$(CDPATH= cd -- "$install_root" && pwd -P)
      if [ "$resolved_root" = "$install_root" ]; then
        /bin/rm -rf "$install_root"
      fi
    fi
    for user in $development_users; do
      /usr/bin/dscl . -delete "/Users/$user" >/dev/null 2>&1 || true
    done
    for group in $development_groups; do
      /usr/bin/dscl . -delete "/Groups/$group" >/dev/null 2>&1 || true
    done
  fi
}
trap cleanup EXIT HUP INT TERM

next_identifier() {
  candidate=$1
  while /usr/bin/dscl . -search /Groups PrimaryGroupID "$candidate" >/dev/null 2>&1 \
    || /usr/bin/dscl . -search /Users UniqueID "$candidate" >/dev/null 2>&1; do
    candidate=$((candidate + 1))
  done
  echo "$candidate"
}

create_group() {
  name=$1
  gid=$2
  /usr/bin/dscl . -create "/Groups/$name"
  /usr/bin/dscl . -create "/Groups/$name" PrimaryGroupID "$gid"
  /usr/bin/dscl . -create "/Groups/$name" RealName "Savana development $name"
}

create_user() {
  name=$1
  uid=$2
  gid=$3
  /usr/bin/dscl . -create "/Users/$name"
  /usr/bin/dscl . -create "/Users/$name" UniqueID "$uid"
  /usr/bin/dscl . -create "/Users/$name" PrimaryGroupID "$gid"
  /usr/bin/dscl . -create "/Users/$name" NFSHomeDirectory /var/empty
  /usr/bin/dscl . -create "/Users/$name" UserShell /usr/bin/false
  /usr/bin/dscl . -create "/Users/$name" IsHidden 1
  /usr/bin/dscl . -create "/Users/$name" RealName "Savana development $name"
}

base_identifier=$(next_identifier 570)
accounts=$development_users
created_groups=""
created_users=""
identifier=$base_identifier
for account in $accounts; do
  create_group "$account" "$identifier"
  created_groups="$created_groups $account"
  create_user "$account" "$identifier" "$identifier"
  created_users="$created_users $account"
  identifier=$((identifier + 1))
done

edge_groups="_savana_runtime_dev _savana_agent_kernel_dev _savana_ingress_kernel_dev _savana_kernel_exec_dev _savana_agent_approval_dev _savana_ingress_approval_dev _savana_jarvis_agent_dev"
for group in $edge_groups; do
  identifier=$(next_identifier "$identifier")
  create_group "$group" "$identifier"
  created_groups="$created_groups $group"
  identifier=$((identifier + 1))
done

add_edge_members() {
  group=$1
  first=$2
  second=$3
  /usr/bin/dscl . -append "/Groups/$group" GroupMembership "$first"
  /usr/bin/dscl . -append "/Groups/$group" GroupMembership "$second"
}
add_edge_members _savana_agent_kernel_dev _savana_agent_dev _savana_kernel_dev
add_edge_members _savana_ingress_kernel_dev _savana_ingress_dev _savana_kernel_dev
add_edge_members _savana_kernel_exec_dev _savana_kernel_dev _savana_exec_dev
add_edge_members _savana_agent_approval_dev _savana_agent_dev _savana_approval_dev
add_edge_members _savana_ingress_approval_dev _savana_ingress_dev _savana_approval_dev
add_edge_members _savana_jarvis_agent_dev _savana_jarvis_dev _savana_agent_dev
for account in $development_users; do
  /usr/bin/dscl . -append /Groups/_savana_runtime_dev GroupMembership "$account"
done

/usr/bin/install -d -o root -g _savana_runtime_dev -m 0750 "$install_root"
for directory in bin config config/tls config/trust credentials libexec log run sandbox state; do
  /usr/bin/install -d -o root -g _savana_runtime_dev -m 0750 "$install_root/$directory"
done
for service in kerneld agentd ingressd approvald execd jarvis-python; do
  case "$service" in
    kerneld) account=_savana_kernel_dev ;;
    agentd) account=_savana_agent_dev ;;
    ingressd) account=_savana_ingress_dev ;;
    approvald) account=_savana_approval_dev ;;
    execd) account=_savana_exec_dev ;;
    jarvis-python) account=_savana_jarvis_dev ;;
  esac
  /usr/bin/install -d -o root -g "$account" -m 0750 "$install_root/credentials/$service"
  /usr/bin/install -d -o "$account" -g "$account" -m 0750 "$install_root/state/$service"
  /usr/bin/install -o "$account" -g "$account" -m 0600 /dev/null \
    "$install_root/log/$service.log"
  /usr/bin/install -o "$account" -g "$account" -m 0600 /dev/null \
    "$install_root/log/$service.error.log"
done
/usr/bin/install -d -o _savana_agent_dev -g _savana_jarvis_agent_dev -m 0770 \
  "$install_root/run/agentd/jarvis"
/usr/bin/install -d -o _savana_kernel_dev -g _savana_agent_kernel_dev -m 0770 \
  "$install_root/run/kerneld/agentd"
/usr/bin/install -d -o _savana_kernel_dev -g _savana_ingress_kernel_dev -m 0770 \
  "$install_root/run/kerneld/ingressd"
/usr/bin/install -d -o _savana_exec_dev -g _savana_kernel_exec_dev -m 0770 \
  "$install_root/run/execd/kerneld"
/usr/bin/install -d -o _savana_approval_dev -g _savana_agent_approval_dev -m 0770 \
  "$install_root/run/approvald/agentd"
/usr/bin/install -d -o _savana_approval_dev -g _savana_ingress_approval_dev -m 0770 \
  "$install_root/run/approvald/ingressd"
/usr/bin/install -d -o _savana_approval_dev -g _savana_approval_dev -m 0700 \
  "$install_root/run/approvald/admin"
/usr/bin/install -d -o _savana_ingress_dev -g _savana_ingress_dev -m 0750 \
  "$install_root/sandbox/ingressd"
/usr/bin/install -d -o _savana_exec_dev -g _savana_exec_dev -m 0750 \
  "$install_root/sandbox/execd"

for service in $labels; do
  /usr/bin/install -o root -g wheel -m 0755 \
    "$build_directory/bin/savana-$service" "$install_root/bin/savana-$service"
  /usr/bin/install -o root -g wheel -m 0444 \
    "$build_directory/entitlements/com.savana.development.$service.plist" \
    "$install_root/config/com.savana.development.$service.entitlements.plist"
done
/usr/bin/install -o _savana_ingress_dev -g _savana_ingress_dev -m 0555 \
  "$build_directory/bin/savana-worker-sandbox" \
  "$install_root/sandbox/ingressd/savana-worker-sandbox"
/usr/bin/install -o _savana_ingress_dev -g _savana_ingress_dev -m 0555 \
  "$build_directory/bin/savana-parser-worker" \
  "$install_root/sandbox/ingressd/savana-parser-worker"
/usr/bin/install -o _savana_exec_dev -g _savana_exec_dev -m 0555 \
  "$build_directory/bin/savana-worker-sandbox" \
  "$install_root/sandbox/execd/savana-worker-sandbox"
/usr/bin/install -o _savana_exec_dev -g _savana_exec_dev -m 0555 \
  "$build_directory/bin/savana-connector-worker" \
  "$install_root/sandbox/execd/savana-connector-worker"
/usr/bin/install -o _savana_ingress_dev -g _savana_ingress_dev -m 0444 \
  "$build_directory/sandbox/parser-profile-v2.json" \
  "$install_root/sandbox/ingressd/parser-profile-v2.json"
/usr/bin/install -o _savana_exec_dev -g _savana_exec_dev -m 0444 \
  "$build_directory/sandbox/connector-no-network-profile-v2.json" \
  "$install_root/sandbox/execd/connector-no-network-profile-v2.json"
/usr/bin/install -o _savana_exec_dev -g _savana_exec_dev -m 0444 \
  "$build_directory/sandbox/connector-credential-absence-profile-v2.json" \
  "$install_root/sandbox/execd/connector-credential-absence-profile-v2.json"
/usr/bin/install -o root -g wheel -m 0755 \
  "$build_directory/libexec/savana-development-manifest" \
  "$install_root/libexec/savana-development-manifest"
/usr/bin/install -o root -g wheel -m 0755 \
  "$build_directory/libexec/savana-development-material" \
  "$install_root/libexec/savana-development-material"
/usr/bin/install -o root -g wheel -m 0755 \
  "$build_directory/libexec/savana-macos-code-identity" \
  "$install_root/libexec/savana-macos-code-identity"

/usr/bin/security create-keychain -p "$keychain_password" "$keychain"
/usr/bin/security unlock-keychain -p "$keychain_password" "$keychain"
/usr/bin/security set-keychain-settings -lut 21600 "$keychain"
/usr/bin/openssl req -x509 -newkey rsa:2048 -nodes -days 30 -sha256 \
  -subj "/CN=Savana Development Code Signing/OU=SAVANADEV1" \
  -addext "basicConstraints=critical,CA:FALSE" \
  -addext "keyUsage=critical,digitalSignature" \
  -addext "extendedKeyUsage=codeSigning" \
  -keyout "$temporary_directory/development.key" \
  -out "$temporary_directory/development.crt"
/usr/bin/openssl pkcs12 -export -legacy \
  -inkey "$temporary_directory/development.key" \
  -in "$temporary_directory/development.crt" \
  -name "Savana Development Code Signing" \
  -passout "pass:$keychain_password" \
  -out "$temporary_directory/development.p12"
/usr/bin/security import "$temporary_directory/development.p12" \
  -k "$keychain" -P "$keychain_password" -T /usr/bin/codesign
/usr/bin/security set-key-partition-list -S apple-tool:,apple: -s \
  -k "$keychain_password" "$keychain" >/dev/null
signing_identity=$(/usr/bin/security find-identity -v -p codesigning "$keychain" \
  | /usr/bin/awk '/Savana Development Code Signing/ { print $2; exit }')
[ -n "$signing_identity" ] || {
  echo "development code-signing identity was not accepted" >&2
  exit 70
}

for service in $labels; do
  /usr/bin/codesign --force --timestamp=none --options runtime \
    --keychain "$keychain" \
    --identifier "com.savana.development.$service" \
    --entitlements "$install_root/config/com.savana.development.$service.entitlements.plist" \
    --sign "$signing_identity" "$install_root/bin/savana-$service"
  /usr/bin/codesign --verify --strict "$install_root/bin/savana-$service"
done
for worker in ingressd/savana-worker-sandbox ingressd/savana-parser-worker; do
  /usr/bin/codesign --force --timestamp=none --options runtime \
    --keychain "$keychain" \
    --identifier "com.savana.development.ingressd.${worker##*/}" \
    --entitlements "$install_root/config/com.savana.development.ingressd.entitlements.plist" \
    --sign "$signing_identity" "$install_root/sandbox/$worker"
  /usr/bin/codesign --verify --strict "$install_root/sandbox/$worker"
done
for worker in execd/savana-worker-sandbox execd/savana-connector-worker; do
  /usr/bin/codesign --force --timestamp=none --options runtime \
    --keychain "$keychain" \
    --identifier "com.savana.development.execd.${worker##*/}" \
    --entitlements "$install_root/config/com.savana.development.execd.entitlements.plist" \
    --sign "$signing_identity" "$install_root/sandbox/$worker"
  /usr/bin/codesign --verify --strict "$install_root/sandbox/$worker"
done

probe="$temporary_directory/savana-signing-probe"
/bin/cp "$install_root/bin/savana-kerneld" "$probe"
/usr/bin/codesign --verify --strict "$probe"
team_identifier=$(/usr/bin/codesign -d --verbose=4 "$probe" 2>&1 \
  | /usr/bin/awk -F= '/^TeamIdentifier=/ { print $2; exit }')
[ "$team_identifier" = "SAVANADEV1" ] || {
  echo "Security.framework Team ID is not SAVANADEV1" >&2
  exit 70
}
"$install_root/libexec/savana-macos-code-identity" "$probe" \
  com.savana.development.kerneld SAVANADEV1 >/dev/null

tls_profile_directory="$script_directory/tls"
runtime_ca_key="$temporary_directory/runtime-ca.key.pem"
runtime_ca_certificate="$temporary_directory/runtime-ca.cert.pem"
/usr/bin/openssl req -x509 -newkey rsa:2048 -nodes -sha256 -days 30 \
  -config "$tls_profile_directory/runtime-ca.cnf" \
  -keyout "$runtime_ca_key" \
  -out "$runtime_ca_certificate"

issue_runtime_certificate() {
  leaf=$1
  common_name=$2
  extension_file=$3
  /usr/bin/openssl req -new -newkey rsa:2048 -nodes -sha256 \
    -subj "/CN=$common_name/OU=SAVANADEV1" \
    -keyout "$temporary_directory/$leaf.key.pem" \
    -out "$temporary_directory/$leaf.csr.pem"
  /usr/bin/openssl x509 -req -sha256 -days 30 \
    -in "$temporary_directory/$leaf.csr.pem" \
    -CA "$runtime_ca_certificate" \
    -CAkey "$runtime_ca_key" \
    -CAcreateserial \
    -extfile "$extension_file" \
    -out "$temporary_directory/$leaf.cert.pem"
  /usr/bin/openssl verify -CAfile "$runtime_ca_certificate" \
    "$temporary_directory/$leaf.cert.pem" >/dev/null
  /usr/bin/openssl x509 -in "$temporary_directory/$leaf.cert.pem" \
    -outform DER -out "$temporary_directory/$leaf.cert.der"
  /usr/bin/openssl pkcs8 -topk8 -nocrypt \
    -in "$temporary_directory/$leaf.key.pem" \
    -outform DER -out "$temporary_directory/$leaf.key.pk8"
}

issue_runtime_certificate planner-server planner.savana-development.invalid \
  "$tls_profile_directory/planner-server.ext"
issue_runtime_certificate planner-client savana-agentd-development \
  "$tls_profile_directory/client.ext"
issue_runtime_certificate provider-server provider.savana-development.invalid \
  "$tls_profile_directory/provider-server.ext"
issue_runtime_certificate provider-client savana-execd-development \
  "$tls_profile_directory/client.ext"

/usr/bin/openssl x509 -in "$runtime_ca_certificate" \
  -outform DER -out "$temporary_directory/runtime-ca.cert.der"
/usr/bin/openssl x509 -in "$temporary_directory/planner-server.cert.pem" \
  -pubkey -noout \
  | /usr/bin/openssl pkey -pubin -outform DER \
    -out "$temporary_directory/planner-server.spki.der"

/usr/bin/install -o root -g wheel -m 0444 \
  "$temporary_directory/runtime-ca.cert.der" \
  "$install_root/config/tls/runtime-root-v2.der"
/usr/bin/install -o root -g wheel -m 0444 \
  "$temporary_directory/planner-server.spki.der" \
  "$install_root/config/tls/planner-server-spki-v2.der"
/usr/bin/install -o root -g wheel -m 0444 \
  "$temporary_directory/provider-client.cert.der" \
  "$install_root/config/tls/provider-client-v2.der"

/usr/bin/install -o root -g _savana_agent_dev -m 0440 \
  "$temporary_directory/runtime-ca.cert.der" \
  "$install_root/credentials/agentd/planner-root-v2.der"
/usr/bin/install -o root -g _savana_agent_dev -m 0440 \
  "$temporary_directory/planner-client.cert.der" \
  "$install_root/credentials/agentd/planner-client-v2.der"
/usr/bin/install -o root -g _savana_agent_dev -m 0440 \
  "$temporary_directory/planner-client.key.pk8" \
  "$install_root/credentials/agentd/planner-client-v2.pk8"
/usr/bin/install -o root -g _savana_exec_dev -m 0440 \
  "$temporary_directory/provider-client.key.pk8" \
  "$install_root/credentials/execd/provider-tls-private-key-v2.der"

for leaf in runtime-ca.cert.pem planner-server.cert.pem planner-server.key.pem \
  provider-server.cert.pem provider-server.key.pem; do
  /usr/bin/install -o root -g _savana_jarvis_dev -m 0440 \
    "$temporary_directory/$leaf" "$install_root/credentials/jarvis-python/$leaf"
done

for service in kerneld agentd ingressd approvald execd; do
  /usr/bin/install -o root -g wheel -m 0444 \
    "$build_directory/config/$service-bootstrap-v2.json" \
    "$install_root/config/$service-bootstrap-v2.json"
done
/usr/bin/install -o root -g wheel -m 0444 \
  "$build_directory/config/jarvis-python-v2.json" \
  "$install_root/config/jarvis-python-v2.json"
/usr/bin/install -o root -g wheel -m 0444 \
  "$build_directory/config/development-manifest-template-v2.json" \
  "$install_root/config/development-manifest-template-v2.json"
/usr/bin/install -o root -g wheel -m 0444 \
  "$build_directory/artifacts/effect-ledger-projection-v2.cbor" \
  "$install_root/config/effect-ledger-projection-v2.cbor"
/usr/bin/install -o root -g wheel -m 0444 \
  "$build_directory/artifacts/input-runtime-assets-v2.cbor" \
  "$install_root/config/input-runtime-assets-v2.cbor"
/usr/bin/install -o root -g _savana_runtime_dev -m 0444 /dev/null \
  "$install_root/config/effect-gate-v2"

SAVANA_AUTHORITY_CLASS=development \
  "$install_root/libexec/savana-development-material" "$install_root"
for service in kerneld agentd ingressd approvald execd jarvis-python; do
  case "$service" in
    kerneld) account=_savana_kernel_dev ;;
    agentd) account=_savana_agent_dev ;;
    ingressd) account=_savana_ingress_dev ;;
    approvald) account=_savana_approval_dev ;;
    execd) account=_savana_exec_dev ;;
    jarvis-python) account=_savana_jarvis_dev ;;
  esac
  /usr/sbin/chown -R "root:$account" "$install_root/credentials/$service"
  /bin/chmod 0750 "$install_root/credentials/$service"
  /usr/bin/find "$install_root/credentials/$service" -type f -exec /bin/chmod 0440 {} \;
done

SAVANA_AUTHORITY_CLASS=development \
  "$install_root/libexec/savana-development-manifest" \
  "$install_root/config/development-manifest-template-v2.json" \
  "$build_directory/signing/deployment-manifest-v2.seed" \
  "$install_root" \
  "$install_root/config/trust/deployment-manifest-root-v2.json" \
  "$install_root/config/deployment-manifest-v2.cbor"

plist_directory=$(CDPATH= cd -- "$script_directory/../../launchd/development" && pwd -P)
installed_plists=""
for service in $labels; do
  target="$launchd_root/com.savana.development.$service.plist"
  /usr/bin/install -o root -g wheel -m 0644 \
    "$plist_directory/com.savana.development.$service.plist" "$target"
  installed_plists="$installed_plists $target"
done

loaded=""
for service in kerneld approvald execd ingressd agentd jarvis-python; do
  plist="$launchd_root/com.savana.development.$service.plist"
  if ! /bin/launchctl bootstrap system "$plist"; then
    for label in $loaded; do
      /bin/launchctl bootout "system/$label" >/dev/null 2>&1 || true
    done
    exit 70
  fi
  loaded="$loaded com.savana.development.$service"
done

deadline=$((SECONDS + 60))
for label in $loaded; do
  while ! /bin/launchctl print "system/$label" 2>/dev/null | /usr/bin/grep -q "state = running"; do
    [ "$SECONDS" -lt "$deadline" ] || {
      for unload in $loaded; do
        /bin/launchctl bootout "system/$unload" >/dev/null 2>&1 || true
      done
      echo "launchd readiness deadline exceeded" >&2
      exit 70
    }
    /bin/sleep 1
  done
done

trap - EXIT HUP INT TERM
installation_committed=1
cleanup
echo "Savana development service graph installed"
