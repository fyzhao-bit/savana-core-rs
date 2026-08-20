#!/bin/bash
set -Eeu
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

require_signed_artifact() {
  path=$1
  [ -f "$path" ] && [ ! -L "$path" ] && [ -x "$path" ] || {
    echo "signed development artifact is missing: $path" >&2
    exit 66
  }
}
for service in kerneld agentd ingressd approvald execd jarvis-python; do
  require_signed_artifact "$build_directory/signed/bin/savana-$service"
done
require_signed_artifact "$build_directory/signed/bin/savana-development-audit-bridge"
for artifact in \
  ingressd/savana-worker-sandbox \
  ingressd/savana-parser-worker \
  execd/savana-worker-sandbox \
  execd/savana-connector-worker; do
  require_signed_artifact "$build_directory/signed/sandbox/$artifact"
done
for helper in savana-development-manifest savana-development-material savana-development-attestation-root savana-macos-code-identity; do
  require_signed_artifact "$build_directory/signed/libexec/$helper"
done

[ "$(/usr/bin/id -u)" -eq 0 ] || {
  echo "install.sh must run as root" >&2
  exit 77
}

install_parent="/Library/Application Support/Savana"
install_root="$install_parent/Development"
log_parent="/Library/Logs/Savana"
log_root="$log_parent/Development"
launcher_root="/Library/PrivilegedHelperTools/SavanaDevelopment"
launchd_root="/Library/LaunchDaemons"
labels="kerneld agentd ingressd approvald execd jarvis-python"
bridge_label="audit-bridge"
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
if [ -e "$install_parent" ]; then
  [ -d "$install_parent" ] && [ ! -L "$install_parent" ] || {
    echo "Savana installation parent is not a real directory" >&2
    exit 73
  }
  resolved_install_parent=$(CDPATH= cd -- "$install_parent" && pwd -P)
  [ "$resolved_install_parent" = "$install_parent" ] || {
    echo "resolved Savana installation parent leaves the fixed path" >&2
    exit 73
  }
  parent_owner=$(/usr/bin/stat -f '%u' "$install_parent")
  parent_mode_text=$(/usr/bin/stat -f '%Lp' "$install_parent")
  parent_mode=$((8#$parent_mode_text))
  [ "$parent_owner" -eq 0 ] && [ $((parent_mode & 0022)) -eq 0 ] || {
    echo "Savana installation parent is not root-owned and closed" >&2
    exit 73
  }
fi
[ ! -e "$log_parent" ] || {
  echo "development log parent already exists" >&2
  exit 73
}
[ ! -e "$launcher_root" ] || {
  echo "development launcher root already exists" >&2
  exit 73
}
for service in $bridge_label $labels; do
  [ ! -e "$launchd_root/com.savana.development.$service.plist" ] || {
    echo "development launchd plist already exists for $service" >&2
    exit 73
  }
done

temporary_directory=$(/usr/bin/mktemp -d "/private/tmp/savana-development-install.XXXXXX")
system_keychain="/Library/Keychains/System.keychain"
certificate_name="Savana Development Code Signing"
system_certificate="$temporary_directory/development-signing.crt"
development_users="_savana_kernel_dev _savana_agent_dev _savana_ingress_dev _savana_approval_dev _savana_exec_dev _savana_jarvis_dev _savana_audit_dev"
product_users="_savana_kernel_dev _savana_agent_dev _savana_ingress_dev _savana_approval_dev _savana_exec_dev _savana_jarvis_dev"
primary_groups="$development_users"
ipc_edge_groups="_savana_agent_kernel_dev _savana_ingress_kernel_dev _savana_kernel_exec_dev _savana_agent_approval_dev _savana_ingress_approval_dev _savana_jarvis_agent_dev"
edge_groups="_savana_runtime_dev $ipc_edge_groups"
development_groups="$primary_groups $edge_groups"
installation_committed=0
created_users=""
created_primary_groups=""
cleanup() {
  /bin/rm -rf "$temporary_directory"
  if [ "$installation_committed" -eq 0 ]; then
    for service in $labels $bridge_label; do
      /bin/launchctl bootout "system/com.savana.development.$service" >/dev/null 2>&1 || true
      /bin/rm -f "$launchd_root/com.savana.development.$service.plist"
    done
    if [ -d "$log_root" ] && [ ! -L "$log_root" ]; then
      failure_log_directory=$(
        /usr/bin/mktemp -d \
          "/private/tmp/savana-development-install-failure.XXXXXX"
      ) || failure_log_directory=
      if [ -n "$failure_log_directory" ]; then
        /bin/cp -R "$log_root" "$failure_log_directory/log" \
          >/dev/null 2>&1 || true
        /usr/sbin/chown -R root:wheel "$failure_log_directory" \
          >/dev/null 2>&1 || true
        /bin/chmod -R go-rwx "$failure_log_directory" \
          >/dev/null 2>&1 || true
        echo "preserved service failure logs: $failure_log_directory" >&2
      fi
    fi
    if [ -e "$log_root" ] && [ ! -L "$log_root" ]; then
      /bin/rm -rf "$log_root"
    fi
    /bin/rmdir "$log_parent" >/dev/null 2>&1 || true
    if [ -e "$launcher_root" ] && [ ! -L "$launcher_root" ]; then
      /bin/rm -rf "$launcher_root"
    fi
    if [ -e "$install_root" ] && [ ! -L "$install_root" ]; then
      resolved_root=$(CDPATH= cd -- "$install_root" && pwd -P)
      if [ "$resolved_root" = "$install_root" ]; then
        /bin/rm -rf "$install_root"
      fi
    fi
    /bin/rmdir "$install_parent" >/dev/null 2>&1 || true
    for user in $created_users; do
      /usr/bin/dscl . -delete "/Users/$user" >/dev/null 2>&1 || true
    done
    for group in $edge_groups; do
      /usr/bin/dscl . -delete "/Groups/$group" >/dev/null 2>&1 || true
    done
    for user in $created_users; do
      /usr/bin/dscl . -delete "/Users/$user" >/dev/null 2>&1 || true
    done
    for group in $created_primary_groups; do
      if ! /usr/bin/dscl . -read "/Users/$group" >/dev/null 2>&1; then
        /usr/bin/dscl . -delete "/Groups/$group" >/dev/null 2>&1 || true
      fi
    done
  fi
}
rollback_on_signal() {
  status=$1
  trap - EXIT HUP INT TERM
  cleanup
  exit "$status"
}
trap cleanup EXIT
trap 'rollback_on_signal 129' HUP
trap 'rollback_on_signal 130' INT
trap 'rollback_on_signal 143' TERM
trap 'status=$?; echo "installation failed at line ${BASH_LINENO[0]}" >&2; exit "$status"' ERR

system_certificate_count=$(
  /usr/bin/security find-certificate -a -c "$certificate_name" \
    -Z "$system_keychain" \
    | /usr/bin/awk '/SHA-256 hash:/ { count += 1 } END { print count + 0 }'
)
[ "$system_certificate_count" -eq 1 ] || {
  echo "expected exactly one system Savana development certificate" >&2
  exit 70
}
/usr/bin/security find-certificate -c "$certificate_name" \
  -p "$system_keychain" >"$system_certificate"
/usr/bin/security verify-cert -q -L -p codeSign \
  -k "$system_keychain" -c "$system_certificate"
expected_certificate_sha1=$(
  /usr/bin/openssl x509 -in "$system_certificate" -noout -fingerprint -sha1 \
    | /usr/bin/awk -F= '{ print $2 }' \
    | /usr/bin/tr -d ':' \
    | /usr/bin/tr 'A-F' 'a-f'
)
[ "${#expected_certificate_sha1}" -eq 40 ] || {
  echo "cannot measure the system Savana development certificate" >&2
  exit 70
}

existing_group_identifiers=$(/usr/bin/dscl . -list /Groups PrimaryGroupID) || {
  echo "cannot enumerate existing group identifiers" >&2
  exit 70
}
existing_user_identifiers=$(/usr/bin/dscl . -list /Users UniqueID) || {
  echo "cannot enumerate existing user identifiers" >&2
  exit 70
}

next_identifier() {
  candidate=$1
  while /usr/bin/printf '%s\n%s\n' \
    "$existing_group_identifiers" \
    "$existing_user_identifiers" \
    | /usr/bin/awk -v candidate="$candidate" \
        '$NF == candidate { found = 1 } END { exit(found ? 0 : 1) }'; do
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

create_deferred_user_attribute() {
  name=$1
  attribute=$2
  value=$3
  /usr/bin/dscl . -create "/Users/$name" "$attribute" "$value" || true
}

read_user_attribute() {
  name=$1
  attribute=$2
  /usr/bin/dscl . -read "/Users/$name" \
    UniqueID PrimaryGroupID NFSHomeDirectory UserShell IsHidden \
    | /usr/bin/awk -v attribute="$attribute" '
        {
          key = $1
          sub(/^dsAttrTypeNative:/, "", key)
        }
        key == (attribute ":") && NF == 2 { print $2; found = 1; exit }
        END { if (!found) exit 1 }
      '
}

verify_user_attribute() {
  name=$1
  attribute=$2
  value=$3
  recorded=$(read_user_attribute "$name" "$attribute") || return 70
  [ "$recorded" = "$value" ] || {
    echo "cannot verify development user attribute: $attribute" >&2
    return 70
  }
}

read_group_identifier() {
  name=$1
  /usr/bin/dscl . -read "/Groups/$name" PrimaryGroupID \
    | /usr/bin/awk '
        $1 == "PrimaryGroupID:" && NF == 2 { print $2; found = 1; exit }
        END { if (!found) exit 1 }
      '
}

verify_group_identifier() {
  name=$1
  expected=$2
  observed=$(read_group_identifier "$name") || return 70
  [ "$observed" = "$expected" ] || {
    echo "cannot verify development group identifier: $name" >&2
    return 70
  }
}

create_user() {
  name=$1
  uid=$2
  gid=$3
  /usr/bin/dscl . -create "/Users/$name"
  create_deferred_user_attribute "$name" UniqueID "$uid"
  /usr/bin/dscl . -create "/Users/$name" PrimaryGroupID "$gid"
  create_deferred_user_attribute "$name" NFSHomeDirectory /var/empty
  /usr/bin/dscl . -create "/Users/$name" UserShell /usr/bin/false
  /usr/bin/dscl . -create "/Users/$name" IsHidden 1
  /usr/bin/dscl . -create "/Users/$name" RealName "Savana development $name"
  verify_user_attribute "$name" UniqueID "$uid"
  verify_user_attribute "$name" NFSHomeDirectory /var/empty
}

accounts=$development_users
existing_account_count=0
for account in $accounts; do
  if read_user_attribute "$account" UniqueID >/dev/null 2>&1; then
    existing_account_count=$((existing_account_count + 1))
  fi
done

verify_existing_user() {
  account=$1
  identifier=$(read_user_attribute "$account" UniqueID) || return 70
  verify_user_attribute "$account" PrimaryGroupID "$identifier"
  verify_user_attribute "$account" NFSHomeDirectory /var/empty
  verify_user_attribute "$account" UserShell /usr/bin/false
  verify_user_attribute "$account" IsHidden 1
  echo "$identifier"
}

ensure_existing_account() {
  account=$1
  identifier=$(verify_existing_user "$account") || return 70
  if read_group_identifier "$account" >/dev/null 2>&1; then
    verify_group_identifier "$account" "$identifier"
    return
  fi
  conflicting_group=$(
    /usr/bin/printf '%s\n' "$existing_group_identifiers" \
      | /usr/bin/awk -v identifier="$identifier" \
          '$NF == identifier { print $1; exit }'
  )
  [ -z "$conflicting_group" ] || {
    echo "primary group identifier is already occupied: $identifier" >&2
    return 70
  }
  created_primary_groups="$created_primary_groups $account"
  create_group "$account" "$identifier"
  existing_group_identifiers="${existing_group_identifiers}
$account $identifier"
  verify_group_identifier "$account" "$identifier"
}

if [ "$existing_account_count" -eq 0 ]; then
  identifier=$(next_identifier 570)
  for account in $accounts; do
    identifier=$(next_identifier "$identifier")
    created_primary_groups="$created_primary_groups $account"
    create_group "$account" "$identifier"
    created_users="$created_users $account"
    create_user "$account" "$identifier" "$identifier"
    identifier=$((identifier + 1))
  done
else
  case "$existing_account_count" in
    6)
      if read_user_attribute _savana_audit_dev UniqueID >/dev/null 2>&1; then
        echo "development daemon accounts are only partially present" >&2
        exit 70
      fi
      for account in $product_users; do
        ensure_existing_account "$account"
      done
      identifier=$(next_identifier 570)
      created_primary_groups="$created_primary_groups _savana_audit_dev"
      create_group _savana_audit_dev "$identifier"
      created_users="$created_users _savana_audit_dev"
      create_user _savana_audit_dev "$identifier" "$identifier"
      identifier=$((identifier + 1))
      ;;
    7)
      for account in $development_users; do
        ensure_existing_account "$account"
      done
      identifier=$(next_identifier 570)
      ;;
    *)
      echo "development daemon accounts are only partially present" >&2
      exit 70
      ;;
  esac
fi

for group in $edge_groups; do
  identifier=$(next_identifier "$identifier")
  create_group "$group" "$identifier"
  identifier=$((identifier + 1))
done

for account in $development_users; do
  if ! read_user_attribute "$account" UniqueID >/dev/null 2>&1; then
    echo "development daemon account is unavailable: $account" >&2
    exit 70
  fi
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

require_group_membership() {
  account=$1
  group=$2
  if ! /usr/bin/id -Gn "$account" \
    | /usr/bin/tr ' ' '\n' \
    | /usr/bin/grep -Fx "$group" >/dev/null; then
    echo "development group membership did not resolve: $account -> $group" >&2
    exit 70
  fi
}

/usr/bin/dscacheutil -flushcache
for account in $development_users; do
  require_group_membership "$account" _savana_runtime_dev
done
require_group_membership _savana_agent_dev _savana_agent_kernel_dev
require_group_membership _savana_kernel_dev _savana_agent_kernel_dev
require_group_membership _savana_ingress_dev _savana_ingress_kernel_dev
require_group_membership _savana_kernel_dev _savana_ingress_kernel_dev
require_group_membership _savana_kernel_dev _savana_kernel_exec_dev
require_group_membership _savana_exec_dev _savana_kernel_exec_dev
require_group_membership _savana_agent_dev _savana_agent_approval_dev
require_group_membership _savana_approval_dev _savana_agent_approval_dev
require_group_membership _savana_ingress_dev _savana_ingress_approval_dev
require_group_membership _savana_approval_dev _savana_ingress_approval_dev
require_group_membership _savana_jarvis_dev _savana_jarvis_agent_dev
require_group_membership _savana_agent_dev _savana_jarvis_agent_dev

for edge_group in $ipc_edge_groups; do
  if /usr/bin/id -Gn _savana_audit_dev \
    | /usr/bin/tr ' ' '\n' \
    | /usr/bin/grep -Fx "$edge_group" >/dev/null; then
    echo "audit bridge account unexpectedly belongs to IPC edge: $edge_group" >&2
    exit 70
  fi
done

/usr/bin/install -d -o root -g wheel -m 0711 "$install_parent"
/usr/bin/install -d -o root -g _savana_runtime_dev -m 0750 "$install_root"
for directory in bin config config/approvald config/policy config/tls config/trust credentials libexec run sandbox state; do
  /usr/bin/install -d -o root -g _savana_runtime_dev -m 0750 "$install_root/$directory"
done
/usr/bin/install -d -o root -g wheel -m 0711 "$log_parent"
/usr/bin/install -d -o root -g wheel -m 0711 "$log_root"
/usr/bin/install -d -o root -g wheel -m 0755 "$launcher_root"
/usr/bin/install -o _savana_audit_dev -g _savana_audit_dev -m 0600 /dev/null \
  "$log_root/audit-bridge.log"
/usr/bin/install -o _savana_audit_dev -g _savana_audit_dev -m 0600 /dev/null \
  "$log_root/audit-bridge.error.log"
/usr/bin/install -o _savana_audit_dev -g _savana_audit_dev -m 0600 /dev/null \
  "$log_root/kerneld-audit.log"
/usr/bin/mkfifo -m 0640 "$install_root/run/kerneld-audit.fifo"
/usr/sbin/chown _savana_kernel_dev:_savana_audit_dev \
  "$install_root/run/kerneld-audit.fifo"
/usr/bin/install -o root -g wheel -m 0755 \
  "$build_directory/signed/bin/savana-development-audit-bridge" \
  "$launcher_root/savana-development-audit-bridge"
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
  /usr/bin/install -d -o "$account" -g "$account" -m 0700 "$install_root/state/$service"
  /usr/bin/install -o "$account" -g "$account" -m 0600 /dev/null \
    "$log_root/$service.log"
  /usr/bin/install -o "$account" -g "$account" -m 0600 /dev/null \
    "$log_root/$service.error.log"
  /usr/bin/install -o root -g wheel -m 0755 \
    "$build_directory/signed/bin/savana-$service" "$launcher_root/savana-$service"
done
/usr/bin/install -d -o _savana_agent_dev -g _savana_jarvis_agent_dev -m 0711 \
  "$install_root/run/agentd/jarvis"
/usr/bin/install -d -o _savana_kernel_dev -g _savana_agent_kernel_dev -m 0711 \
  "$install_root/run/kerneld/agentd"
/usr/bin/install -d -o _savana_kernel_dev -g _savana_ingress_kernel_dev -m 0770 \
  "$install_root/run/kerneld/ingressd"
/usr/bin/install -d -o _savana_exec_dev -g _savana_kernel_exec_dev -m 0711 \
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
    "$build_directory/signed/bin/savana-$service" "$install_root/bin/savana-$service"
  /usr/bin/install -o root -g wheel -m 0444 \
    "$build_directory/entitlements/com.savana.development.$service.plist" \
    "$install_root/config/com.savana.development.$service.entitlements.plist"
done
/usr/bin/install -o root -g wheel -m 0755 \
  "$build_directory/signed/bin/savana-development-audit-bridge" \
  "$install_root/bin/savana-development-audit-bridge"
/usr/bin/install -o _savana_ingress_dev -g _savana_ingress_dev -m 0555 \
  "$build_directory/signed/sandbox/ingressd/savana-worker-sandbox" \
  "$install_root/sandbox/ingressd/savana-worker-sandbox"
/usr/bin/install -o _savana_ingress_dev -g _savana_ingress_dev -m 0555 \
  "$build_directory/signed/sandbox/ingressd/savana-parser-worker" \
  "$install_root/sandbox/ingressd/savana-parser-worker"
/usr/bin/install -o _savana_exec_dev -g _savana_exec_dev -m 0555 \
  "$build_directory/signed/sandbox/execd/savana-worker-sandbox" \
  "$install_root/sandbox/execd/savana-worker-sandbox"
/usr/bin/install -o _savana_exec_dev -g _savana_exec_dev -m 0555 \
  "$build_directory/signed/sandbox/execd/savana-connector-worker" \
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
  "$build_directory/signed/libexec/savana-development-manifest" \
  "$install_root/libexec/savana-development-manifest"
/usr/bin/install -o root -g wheel -m 0755 \
  "$build_directory/signed/libexec/savana-development-material" \
  "$install_root/libexec/savana-development-material"
/usr/bin/install -o root -g wheel -m 0755 \
  "$build_directory/signed/libexec/savana-development-attestation-root" \
  "$install_root/libexec/savana-development-attestation-root"
/usr/bin/install -o root -g wheel -m 0755 \
  "$build_directory/signed/libexec/savana-macos-code-identity" \
  "$install_root/libexec/savana-macos-code-identity"

verify_installed_identity() {
  path=$1
  identifier=$2
  test_requirement="certificate root = H\"$expected_certificate_sha1\" and identifier \"$identifier\""
  /usr/bin/codesign --verify --strict -R="$test_requirement" "$path"
  observed=$(/usr/bin/codesign -d --verbose=4 "$path" 2>&1)
  observed_identifier=$(
    /usr/bin/printf '%s\n' "$observed" \
      | /usr/bin/awk -F= '/^Identifier=/ { print $2; exit }'
  )
  team_identifier=$(
    /usr/bin/printf '%s\n' "$observed" \
      | /usr/bin/awk -F= '/^TeamIdentifier=/ { print $2; exit }'
  )
  [ "$observed_identifier" = "$identifier" ] || {
    echo "Security.framework bundle ID does not match: $identifier" >&2
    exit 70
  }
  [ "$team_identifier" = "not set" ] || {
    echo "signed development code contains an unexpected Apple Team ID" >&2
    exit 70
  }
  "$install_root/libexec/savana-macos-code-identity" \
    "$path" "$identifier" SAVANADEV1 >/dev/null
}
for service in $labels; do
  verify_installed_identity \
    "$install_root/bin/savana-$service" \
    "com.savana.development.$service"
  verify_installed_identity "$launcher_root/savana-$service" \
    "com.savana.development.$service"
  /usr/bin/cmp -s "$install_root/bin/savana-$service" "$launcher_root/savana-$service"
done
verify_installed_identity \
  "$install_root/bin/savana-development-audit-bridge" \
  "com.savana.development.audit-bridge"
verify_installed_identity \
  "$launcher_root/savana-development-audit-bridge" \
  "com.savana.development.audit-bridge"
/usr/bin/cmp -s \
  "$install_root/bin/savana-development-audit-bridge" \
  "$launcher_root/savana-development-audit-bridge"
for worker in ingressd/savana-worker-sandbox ingressd/savana-parser-worker; do
  verify_installed_identity \
    "$install_root/sandbox/$worker" \
    "com.savana.development.ingressd.${worker##*/}"
done
for worker in execd/savana-worker-sandbox execd/savana-connector-worker; do
  verify_installed_identity \
    "$install_root/sandbox/$worker" \
    "com.savana.development.execd.${worker##*/}"
done
for helper in savana-development-manifest savana-development-material savana-development-attestation-root savana-macos-code-identity; do
  verify_installed_identity \
    "$install_root/libexec/$helper" \
    "com.savana.development.$helper"
done

probe="$temporary_directory/savana-signing-probe"
/bin/cp "$install_root/bin/savana-kerneld" "$probe"
/usr/bin/codesign --verify --strict "$probe"
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
issue_runtime_certificate mapper-server mapper.savana-development.invalid \
  "$tls_profile_directory/mapper-server.ext"
issue_runtime_certificate mapper-client savana-agentd-mapper-development \
  "$tls_profile_directory/client.ext"
issue_runtime_certificate provider-server provider.savana-development.invalid \
  "$tls_profile_directory/provider-server.ext"
issue_runtime_certificate provider-client savana-execd-development \
  "$tls_profile_directory/client.ext"
issue_runtime_certificate final-release-server release.savana-development.invalid \
  "$tls_profile_directory/final-release-server.ext"
issue_runtime_certificate final-release-client savana-execd-final-release-development \
  "$tls_profile_directory/client.ext"

attestation_aaguid=534156414e4144455631000000000001
attestation_root_measurement=$(
  "$install_root/libexec/savana-development-attestation-root" \
    "$temporary_directory/webauthn-attestation-root.cert.der" \
    "$attestation_aaguid"
)
/usr/bin/openssl x509 -in "$runtime_ca_certificate" \
  -outform DER -out "$temporary_directory/runtime-ca.cert.der"
/usr/bin/openssl x509 -in "$temporary_directory/planner-server.cert.pem" \
  -pubkey -noout \
  | /usr/bin/openssl pkey -pubin -outform DER \
    -out "$temporary_directory/planner-server.spki.der"
/usr/bin/openssl x509 -in "$temporary_directory/mapper-server.cert.pem" \
  -pubkey -noout \
  | /usr/bin/openssl pkey -pubin -outform DER \
    -out "$temporary_directory/mapper-server.spki.der"
/usr/bin/openssl x509 -in "$temporary_directory/provider-server.cert.pem" \
  -pubkey -noout \
  | /usr/bin/openssl pkey -pubin -outform DER \
    -out "$temporary_directory/provider-server.spki.der"
/usr/bin/openssl x509 -in "$temporary_directory/final-release-server.cert.pem" \
  -pubkey -noout \
  | /usr/bin/openssl pkey -pubin -outform DER \
    -out "$temporary_directory/final-release-server.spki.der"

/usr/bin/install -o root -g wheel -m 0444 \
  "$temporary_directory/runtime-ca.cert.der" \
  "$install_root/config/tls/runtime-root-v2.der"
/usr/bin/install -o root -g wheel -m 0444 \
  "$temporary_directory/planner-server.spki.der" \
  "$install_root/config/tls/planner-server-spki-v2.der"
/usr/bin/install -o root -g wheel -m 0444 \
  "$temporary_directory/mapper-server.spki.der" \
  "$install_root/config/tls/mapper-server-spki-v2.der"
/usr/bin/install -o root -g wheel -m 0444 \
  "$temporary_directory/provider-server.spki.der" \
  "$install_root/config/tls/provider-server-spki-v2.der"
/usr/bin/install -o root -g wheel -m 0444 \
  "$temporary_directory/provider-client.cert.der" \
  "$install_root/config/tls/provider-client-v2.der"
/usr/bin/install -o root -g wheel -m 0444 \
  "$temporary_directory/final-release-server.spki.der" \
  "$install_root/config/tls/final-release-server-spki-v2.der"
/usr/bin/install -o root -g wheel -m 0444 \
  "$temporary_directory/final-release-client.cert.der" \
  "$install_root/config/tls/final-release-client-v2.der"
/usr/bin/install -o root -g wheel -m 0444 \
  "$temporary_directory/webauthn-attestation-root.cert.der" \
  "$install_root/config/approvald/development-webauthn-attestation-root-v2.der"

/usr/bin/install -o root -g _savana_agent_dev -m 0440 \
  "$temporary_directory/runtime-ca.cert.der" \
  "$install_root/credentials/agentd/planner-root-v2.der"
/usr/bin/install -o root -g _savana_agent_dev -m 0440 \
  "$temporary_directory/planner-client.cert.der" \
  "$install_root/credentials/agentd/planner-client-v2.der"
/usr/bin/install -o root -g _savana_agent_dev -m 0440 \
  "$temporary_directory/planner-client.key.pk8" \
  "$install_root/credentials/agentd/planner-client-v2.pk8"
/usr/bin/install -o root -g _savana_agent_dev -m 0440 \
  "$temporary_directory/runtime-ca.cert.der" \
  "$install_root/credentials/agentd/mapper-root-v2.der"
/usr/bin/install -o root -g _savana_agent_dev -m 0440 \
  "$temporary_directory/mapper-client.cert.der" \
  "$install_root/credentials/agentd/mapper-client-v2.der"
/usr/bin/install -o root -g _savana_agent_dev -m 0440 \
  "$temporary_directory/mapper-client.key.pk8" \
  "$install_root/credentials/agentd/mapper-client-v2.pk8"
/usr/bin/install -o root -g _savana_exec_dev -m 0440 \
  "$temporary_directory/provider-client.key.pk8" \
  "$install_root/credentials/execd/provider-tls-private-key-v2.der"
/usr/bin/install -o root -g _savana_exec_dev -m 0440 \
  "$temporary_directory/final-release-client.key.pk8" \
  "$install_root/credentials/execd/final-release-provider-tls-private-key-v2.der"

for leaf in runtime-ca.cert.pem planner-server.cert.pem planner-server.key.pem \
  mapper-server.cert.pem mapper-server.key.pem \
  provider-server.cert.pem provider-server.key.pem \
  final-release-server.cert.pem final-release-server.key.pem; do
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
/usr/bin/install -o root -g wheel -m 0444 \
  "$build_directory/artifacts/development-draft-report-tool-v2.cbor" \
  "$install_root/config/policy/development-draft-report-tool-v2.cbor"
/usr/bin/install -o root -g wheel -m 0444 \
  "$build_directory/artifacts/declassification-installer-root-v2.json" \
  "$install_root/config/trust/declassification-installer-root-v2.json"
/usr/bin/install -o root -g wheel -m 0444 \
  "$build_directory/artifacts/declassification-trust-root-set-v2.cbor" \
  "$install_root/config/trust/declassification-trust-root-set-v2.cbor"
/usr/bin/install -o root -g wheel -m 0444 \
  "$build_directory/artifacts/declassification-rule-set-v2.cbor" \
  "$install_root/config/policy/declassification-rule-set-v2.cbor"
/usr/bin/install -o root -g _savana_runtime_dev -m 0444 /dev/null \
  "$install_root/config/effect-gate-v2"

attestation_root_certificate_sha256=$(
  /usr/bin/printf '%s\n' "$attestation_root_measurement" \
  | /usr/bin/awk '{ print $1 }'
)
attestation_root_spki_sha256=$(
  /usr/bin/printf '%s\n' "$attestation_root_measurement" \
  | /usr/bin/awk '{ print $2 }'
)
case "$attestation_root_certificate_sha256:$attestation_root_spki_sha256" in
  *[!0-9a-f:]*|:*|*:) echo "invalid development attestation digest" >&2; exit 70 ;;
esac
attestation_roots_json=$(
  /usr/bin/printf \
    '[{"aaguid":"%s","root_certificate_path":"%s","root_certificate_sha256":"%s","root_spki_sha256":"%s"}]' \
    "$attestation_aaguid" \
    "$install_root/config/approvald/development-webauthn-attestation-root-v2.der" \
    "$attestation_root_certificate_sha256" \
    "$attestation_root_spki_sha256"
)
/usr/bin/plutil -replace attestation_roots -json "$attestation_roots_json" \
  "$install_root/config/approvald-bootstrap-v2.json"

harden_generated_trust_file() {
  /usr/sbin/chown root:wheel "$1"
  /bin/chmod 0444 "$1"
}

harden_generated_public_keys() {
  /usr/bin/find "$install_root/config" -type f -name '*.pub' -exec /usr/sbin/chown root:wheel {} \;
  /usr/bin/find "$install_root/config" -type f -name '*.pub' -exec /bin/chmod 0444 {} \;
}

SAVANA_AUTHORITY_CLASS=development \
  "$install_root/libexec/savana-development-material" "$install_root"
connector_authority_credential="$install_root/credentials/kerneld/connector-authority-v2.seed"
connector_authority_key_id=$(
  /usr/bin/plutil -extract policy_runtime.connector_authority_key_id raw -expect string \
    "$install_root/config/kerneld-bootstrap-v2.json"
)
connector_authority_public_key=$(
  /usr/bin/plutil -extract policy_runtime.connector_authority_public_key raw -expect string \
    "$install_root/config/kerneld-bootstrap-v2.json"
)
zero_connector_authority=0000000000000000000000000000000000000000000000000000000000000000
if [ "$connector_authority_key_id" = "$zero_connector_authority" ] && \
   [ "$connector_authority_public_key" = "$zero_connector_authority" ]; then
  [ ! -e "$connector_authority_credential" ] || {
    echo "disabled connector authority unexpectedly materialized a private credential" >&2
    exit 70
  }
else
  [ "$connector_authority_key_id" != "$zero_connector_authority" ] && \
    [ "$connector_authority_public_key" != "$zero_connector_authority" ] && \
    [ -f "$connector_authority_credential" ] && \
    [ ! -L "$connector_authority_credential" ] && \
    [ "$(/usr/bin/stat -f %z "$connector_authority_credential")" = "32" ] || {
      echo "enabled connector authority has incomplete private material" >&2
      exit 70
    }
fi
/usr/sbin/chown _savana_ingress_dev:_savana_ingress_dev \
  "$install_root/sandbox/ingressd/parser-profile-v2.json"
/bin/chmod 0444 "$install_root/sandbox/ingressd/parser-profile-v2.json"
/usr/sbin/chown _savana_exec_dev:_savana_exec_dev \
  "$install_root/sandbox/execd/connector-credential-absence-profile-v2.json"
/bin/chmod 0444 \
  "$install_root/sandbox/execd/connector-credential-absence-profile-v2.json"
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
harden_generated_public_keys
for service in kerneld agentd ingressd approvald execd; do
  harden_generated_trust_file "$install_root/config/$service-bootstrap-v2.json"
done
harden_generated_trust_file "$install_root/config/jarvis-python-v2.json"
harden_generated_trust_file "$install_root/config/development-manifest-template-v2.json"
harden_generated_trust_file "$install_root/config/trust/deployment-manifest-root-v2.json"
harden_generated_trust_file "$install_root/config/trust/declassification-installer-root-v2.json"
harden_generated_trust_file "$install_root/config/trust/declassification-trust-root-set-v2.cbor"
harden_generated_trust_file "$install_root/config/policy/declassification-rule-set-v2.cbor"
harden_generated_trust_file "$install_root/config/deployment-manifest-v2.cbor"

plist_directory=$(CDPATH= cd -- "$script_directory/../../launchd/development" && pwd -P)
installed_plists=""
for service in $bridge_label $labels; do
  target="$launchd_root/com.savana.development.$service.plist"
  /usr/bin/install -o root -g wheel -m 0644 \
    "$plist_directory/com.savana.development.$service.plist" "$target"
  installed_plists="$installed_plists $target"
done

materialize_socket_identity() {
  service=$1
  socket=$2
  owner_name=$3
  group_name=$4
  target="$launchd_root/com.savana.development.$service.plist"
  owner=$(/usr/bin/id -u "$owner_name") || exit 70
  group=$(read_group_identifier "$group_name") || exit 70
  case "$owner:$group" in
    *[!0-9:]*|:*|*:) echo "invalid numeric launchd socket identity" >&2; exit 70 ;;
  esac
  /usr/libexec/PlistBuddy -c "Delete :Sockets:$socket:SockPathOwner" "$target"
  /usr/libexec/PlistBuddy -c "Add :Sockets:$socket:SockPathOwner integer $owner" "$target"
  /usr/libexec/PlistBuddy -c "Delete :Sockets:$socket:SockPathGroup" "$target"
  /usr/libexec/PlistBuddy -c "Add :Sockets:$socket:SockPathGroup integer $group" "$target"
}
materialize_socket_identity agentd savana-jarvis-agent-control _savana_agent_dev _savana_jarvis_agent_dev
materialize_socket_identity kerneld savana-agent-kernel _savana_kernel_dev _savana_agent_kernel_dev
materialize_socket_identity kerneld savana-ingress-kernel _savana_kernel_dev _savana_ingress_kernel_dev
materialize_socket_identity approvald savana-agent-approval _savana_approval_dev _savana_agent_approval_dev
materialize_socket_identity approvald savana-ingress-approval _savana_approval_dev _savana_ingress_approval_dev
materialize_socket_identity approvald savana-admin-approval root wheel
materialize_socket_identity execd savana-kernel-executor _savana_exec_dev _savana_kernel_exec_dev
for plist in $installed_plists; do
  /usr/bin/plutil -lint "$plist" >/dev/null
done

loaded=""
bridge_plist="$launchd_root/com.savana.development.$bridge_label.plist"
if ! /bin/launchctl bootstrap system "$bridge_plist"; then
  exit 70
fi
loaded="com.savana.development.$bridge_label"
if ! /bin/launchctl kickstart -k "system/com.savana.development.$bridge_label"; then
  /bin/launchctl bootout "system/com.savana.development.$bridge_label" \
    >/dev/null 2>&1 || true
  exit 70
fi
bridge_deadline=$((SECONDS + 15))
while ! /bin/launchctl print "system/com.savana.development.$bridge_label" 2>/dev/null \
  | /usr/bin/grep -q "state = running"; do
  [ "$SECONDS" -lt "$bridge_deadline" ] || {
    /bin/launchctl bootout "system/com.savana.development.$bridge_label" \
      >/dev/null 2>&1 || true
    echo "audit bridge readiness deadline exceeded" >&2
    exit 70
  }
  /bin/sleep 1
done
/bin/sleep 1
/bin/launchctl print "system/com.savana.development.$bridge_label" 2>/dev/null \
  | /usr/bin/grep -q "state = running" || {
  /bin/launchctl bootout "system/com.savana.development.$bridge_label" \
    >/dev/null 2>&1 || true
  echo "audit bridge did not remain running" >&2
  exit 70
}

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

/usr/sbin/chown root:wheel \
  "$install_root/run/approvald/admin/approvald.sock"
/bin/chmod 0600 "$install_root/run/approvald/admin/approvald.sock"

deadline=$((SECONDS + 60))
for service in kerneld approvald execd ingressd agentd jarvis-python; do
  label="com.savana.development.$service"
  if ! /bin/launchctl kickstart -k "system/com.savana.development.$service"; then
    for unload in $loaded; do
      /bin/launchctl bootout "system/$unload" >/dev/null 2>&1 || true
    done
    exit 70
  fi
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

wait_for_v2_ui() {
  ui_deadline=$((SECONDS + 180))
  while [ "$SECONDS" -lt "$ui_deadline" ]; do
    if /usr/bin/curl --fail --silent --max-time 2 \
      --resolve localhost:8765:127.0.0.1 \
      http://localhost:8765/v2/shell >/dev/null; then
      return 0
    fi
    /bin/sleep 1
  done
  echo "V2 UI readiness deadline exceeded" >&2
  return 70
}

wait_for_v2_ui

snapshot_launchd_pid() {
  /bin/launchctl print "system/$1" 2>/dev/null \
    | /usr/bin/awk '$1 == "pid" && $2 == "=" { print $3; exit }'
}

stability_deadline=$((SECONDS + 90))
while :; do
  snapshot_complete=1
  for service in audit-bridge kerneld approvald execd ingressd agentd jarvis-python; do
    label="com.savana.development.$service"
    pid=$(snapshot_launchd_pid "$label")
    case "$pid" in
      ''|*[!0-9]*) snapshot_complete=0 ;;
      *) /usr/bin/printf '%s\n' "$pid" >"$temporary_directory/$service.pid" ;;
    esac
  done

  graph_stable=0
  if [ "$snapshot_complete" -eq 1 ]; then
    /bin/sleep 15
    graph_stable=1
    for service in audit-bridge kerneld approvald execd ingressd agentd jarvis-python; do
      label="com.savana.development.$service"
      expected_pid=$(/bin/cat "$temporary_directory/$service.pid")
      observed_pid=$(snapshot_launchd_pid "$label")
      if [ "$observed_pid" != "$expected_pid" ] \
        || ! /bin/launchctl print "system/$label" 2>/dev/null \
          | /usr/bin/grep -q "state = running"; then
        graph_stable=0
        break
      fi
    done
  fi

  [ "$graph_stable" -eq 1 ] && break
  [ "$SECONDS" -lt "$stability_deadline" ] || {
    echo "launchd service graph did not converge to stable PIDs" >&2
    exit 70
  }
  [ "$snapshot_complete" -eq 1 ] || /bin/sleep 1
done

trap - EXIT HUP INT TERM
installation_committed=1
cleanup
echo "Savana development service graph installed"
