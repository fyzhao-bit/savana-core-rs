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

install_root="/Library/Application Support/Savana/Development"
launchd_root="/Library/LaunchDaemons"
labels="kerneld agentd ingressd approvald execd jarvis-python"

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

for service in $labels; do
  /bin/launchctl bootout "system/com.savana.development.$service" >/dev/null 2>&1 || true
done
for service in $labels; do
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

users="_savana_kernel_dev _savana_agent_dev _savana_ingress_dev _savana_approval_dev _savana_exec_dev _savana_jarvis_dev"
groups="$users _savana_runtime_dev _savana_agent_kernel_dev _savana_ingress_kernel_dev _savana_kernel_exec_dev _savana_agent_approval_dev _savana_ingress_approval_dev _savana_jarvis_agent_dev"
for user in $users; do
  /usr/bin/dscl . -delete "/Users/$user" >/dev/null 2>&1 || true
done
for group in $groups; do
  /usr/bin/dscl . -delete "/Groups/$group" >/dev/null 2>&1 || true
done

echo "Savana development service graph removed"
