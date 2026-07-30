#!/bin/bash
set -eu

usage() {
  echo "usage: uninstall.sh" >&2
  exit 64
}

[ "$#" -eq 0 ] || usage
[ "$(/usr/bin/id -u)" -eq 0 ] || {
  echo "uninstall.sh must run as root" >&2
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

if [ -e "$install_root" ]; then
  [ ! -L "$install_root" ] || {
    echo "refusing to remove a symlinked development root" >&2
    exit 73
  }
  resolved_root=$(CDPATH= cd -- "$install_root" && pwd -P)
  [ "$resolved_root" = "$install_root" ] || {
    echo "resolved development root leaves the fixed path" >&2
    exit 73
  }
fi
if [ -e "$log_root" ]; then
  [ ! -L "$log_root" ] || {
    echo "refusing to remove a symlinked development log root" >&2
    exit 73
  }
  resolved_log_root=$(CDPATH= cd -- "$log_root" && pwd -P)
  [ "$resolved_log_root" = "$log_root" ] || {
    echo "resolved development log root leaves the fixed path" >&2
    exit 73
  }
fi
if [ -e "$launcher_root" ]; then
  [ ! -L "$launcher_root" ] || {
    echo "refusing to remove a symlinked development launcher root" >&2
    exit 73
  }
  resolved_launcher_root=$(CDPATH= cd -- "$launcher_root" && pwd -P)
  [ "$resolved_launcher_root" = "$launcher_root" ] || {
    echo "resolved development launcher root leaves the fixed path" >&2
    exit 73
  }
fi

for service in $labels; do
  /bin/launchctl bootout "system/com.savana.development.$service" >/dev/null 2>&1 || true
done
/bin/launchctl bootout "system/com.savana.development.$bridge_label" >/dev/null 2>&1 || true
for service in $bridge_label $labels; do
  plist="$launchd_root/com.savana.development.$service.plist"
  if [ -e "$plist" ]; then
    [ ! -L "$plist" ] || {
      echo "refusing to remove symlinked launchd plist: $plist" >&2
      exit 73
    }
    /bin/rm -f "$plist"
  fi
done
if [ -e "$install_root" ]; then
  /bin/rm -rf "$install_root"
fi
/bin/rmdir "$install_parent" >/dev/null 2>&1 || true
if [ -e "$log_root" ]; then
  /bin/rm -rf "$log_root"
fi
/bin/rmdir "$log_parent" >/dev/null 2>&1 || true
if [ -e "$launcher_root" ]; then
  /bin/rm -rf "$launcher_root"
fi

users="_savana_kernel_dev _savana_agent_dev _savana_ingress_dev _savana_approval_dev _savana_exec_dev _savana_jarvis_dev _savana_audit_dev"
groups="_savana_runtime_dev _savana_agent_kernel_dev _savana_ingress_kernel_dev _savana_kernel_exec_dev _savana_agent_approval_dev _savana_ingress_approval_dev _savana_jarvis_agent_dev"

delete_directory_record() {
  record_type=$1
  name=$2
  path="/$record_type/$name"
  attempts=0
  while /usr/bin/dscl . -read "$path" >/dev/null 2>&1; do
    /usr/bin/dscl . -delete "$path" >/dev/null 2>&1 || true
    attempts=$((attempts + 1))
    [ "$attempts" -lt 10 ] || {
      echo "cannot remove development directory record: $path" >&2
      exit 70
    }
    /usr/bin/dscacheutil -flushcache
    /bin/sleep 1
  done
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

verify_locked_service_account() {
  user=$1
  identifier=$(read_user_attribute "$user" UniqueID) || return 70
  case "$identifier" in
    ''|*[!0-9]*) return 70 ;;
  esac
  [ "$identifier" -gt 0 ] \
    && [ "$(read_user_attribute "$user" PrimaryGroupID)" = "$identifier" ] \
    && [ "$(read_user_attribute "$user" NFSHomeDirectory)" = /var/empty ] \
    && [ "$(read_user_attribute "$user" UserShell)" = /usr/bin/false ] \
    && [ "$(read_user_attribute "$user" IsHidden)" = 1 ] \
    && [ "$(/usr/bin/dscl . -read "/Groups/$user" PrimaryGroupID \
      | /usr/bin/awk '$1 == "PrimaryGroupID:" && NF == 2 { print $2; exit }')" = "$identifier" ] || {
      echo "refusing to retain an unsafe development service identity: $user" >&2
      return 70
    }
}

for user in $users; do
  verify_locked_service_account "$user"
done
for group in $groups; do
  delete_directory_record Groups "$group"
done
/usr/bin/dscacheutil -flushcache

echo "Savana development service graph removed; locked development service identities retained"
