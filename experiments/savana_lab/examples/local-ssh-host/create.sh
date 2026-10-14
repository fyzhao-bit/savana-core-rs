#!/bin/bash
# SshHosts' create command for a local stand-in machine: a brand-new
# privileged systemd container (image savana-lab-sshd:24.04, built from this
# directory's Dockerfile) with a fresh SSH host key, reached at
# root@127.0.0.1:2222 with the key $SAVANA_LAB_SSH_KEY (its .pub is
# authorized). Prints the address, then the host key to pin.
set -euo pipefail
name=savana-lab-ssh
key=${SAVANA_LAB_SSH_KEY:?the login key whose .pub to authorize}
docker rm -f "$name" >/dev/null 2>&1 || true
docker run -d --name "$name" --privileged --network host --cgroupns=host -v /sys/fs/cgroup:/sys/fs/cgroup:rw \
  --tmpfs /run --tmpfs /run/lock --tmpfs /tmp savana-lab-sshd:24.04 >/dev/null
for _ in $(seq 60); do
  state=$(docker exec "$name" systemctl is-system-running 2>/dev/null || true)
  case "$state" in running|degraded) break ;; esac
  sleep 1
done
docker exec "$name" ssh-keygen -A >/dev/null
docker exec -i "$name" sh -c 'umask 077; mkdir -p /root/.ssh; cat > /root/.ssh/authorized_keys' < "$key.pub"
docker exec "$name" systemctl start ssh
echo "root@127.0.0.1:2222"
docker exec "$name" cat /etc/ssh/ssh_host_ed25519_key.pub
