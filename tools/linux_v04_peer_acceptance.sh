#!/bin/bash
# Synthetic cross-UID deployment diagnostic. Never run on a production host.
set -eu
test "${1:-}" = --disposable-test-host
test "$(id -u)" = 0
test -f /run/savana-peer-probe/disposable-test-host
probe=/usr/local/libexec/savana-acceptance-peer-probe
test -x "$probe"
test "$(stat -c '%u:%g:%a' "$probe")" = 0:0:755
test "$(id -u savana-probe-a)" != 0
test "$(id -u savana-probe-b)" != 0
test "$(id -u savana-probe-a)" != "$(id -u savana-probe-b)"
scratch=$(mktemp -d /run/savana-peer-probe/case.XXXXXXXX)
chown savana-probe-a:savana-probe-ipc "$scratch"
chmod 2770 "$scratch"

run_case() {
    label=$1
    client_user=$2
    hardened=$3
    socket="$scratch/$label.sock"
    if test "$hardened" = yes; then
        systemd-run --quiet --wait --pipe --collect --unit="savana-probe-$label" \
            -p User=savana-probe-a -p Group=savana-probe-a \
            -p SupplementaryGroups=savana-probe-ipc \
            -p NoNewPrivileges=yes -p CapabilityBoundingSet= -p AmbientCapabilities= \
            -p PrivateTmp=yes -p PrivateDevices=yes -p DevicePolicy=closed \
            -p ProtectSystem=strict -p ProtectHome=yes \
            -p ProtectProc=invisible -p ProcSubset=pid \
            -p RestrictNamespaces=yes -p RestrictSUIDSGID=yes \
            -p LockPersonality=yes -p MemoryDenyWriteExecute=yes \
            -p RestrictAddressFamilies=AF_UNIX -p IPAddressDeny=any \
            -p "ReadWritePaths=$scratch" \
            -p SystemCallArchitectures=native -p SystemCallFilter=@system-service \
            -p 'SystemCallFilter=~@clock @debug @module @mount @obsolete @privileged @raw-io @reboot @swap' \
            -p SystemCallErrorNumber=EPERM \
            "$probe" server "$socket" >"$scratch/$label.log" 2>&1 &
    else
        runuser -u savana-probe-a -- "$probe" server "$socket" >"$scratch/$label.log" 2>&1 &
    fi
    server=$!
    for attempt in $(seq 1 100); do
        test ! -S "$socket" || break
        kill -0 "$server" 2>/dev/null || break
        sleep 0.1
    done
    client_status=0
    if test -S "$socket"; then
        runuser -u "$client_user" -- "$probe" client "$socket" || client_status=$?
    else
        client_status=99
    fi
    server_status=0
    wait "$server" || server_status=$?
    printf 'case=%s server_exit=%s client_exit=%s\n' "$label" "$server_status" "$client_status"
    cat "$scratch/$label.log"
}

run_case same-uid savana-probe-a no
run_case cross-uid savana-probe-b no
run_case hardened-same-uid savana-probe-a yes
run_case hardened-cross-uid savana-probe-b yes
printf 'diagnostic_only=true production_acceptance=not_established\n'
