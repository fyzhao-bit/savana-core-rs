#!/usr/bin/env bash
# A disposable local container for the UNDEFENDED AgentDojo baseline
# (`python -m savana_bench.official_remote --docker NAME ...`): the host
# image's systemd and AgentDojo venv, this checkout's committed experiments/
# as the runner (root's, read only), and a 0700 results directory for the
# unprivileged runner user. No model key ever enters it: the local
# coordinator relays each model call over the runner's framed channel, and
# the runner's own sandbox has no network.
#
#   experiments/savana_lab/examples/baseline-container.sh [NAME]   # default: savana-baseline
#
# The image is the one savana_lab builds for its batches (savana-b-host:24.04).
# Running it again replaces the container (and its results directory).
set -euo pipefail
name=${1:-savana-baseline}
image=savana-b-host:24.04
repo=$(git -C "$(dirname "$0")" rev-parse --show-toplevel)

if ! docker image inspect "$image" >/dev/null 2>&1; then
  echo "no $image here: run one savana_lab batch first (it builds the image)" >&2
  exit 1
fi
docker rm -f "$name" >/dev/null 2>&1 || true
docker run -d --name "$name" --privileged --network host --cgroupns=host \
  -v /sys/fs/cgroup:/sys/fs/cgroup:rw --tmpfs /run --tmpfs /run/lock --tmpfs /tmp "$image" >/dev/null
state=
for _ in $(seq 60); do
  state=$(docker exec "$name" systemctl is-system-running 2>/dev/null || true)
  if [ "$state" = running ] || [ "$state" = degraded ]; then break; fi
  sleep 1
done
if [ "$state" != running ] && [ "$state" != degraded ]; then
  echo "systemd in $name did not come up ($state)" >&2
  exit 1
fi
docker exec "$name" sh -c 'id savana-experiment >/dev/null 2>&1 ||
    useradd --system --user-group --no-create-home --shell /usr/sbin/nologin savana-experiment
  mkdir -p /opt/savana-baseline /opt/savana-baseline-results'
git -C "$repo" archive HEAD experiments | docker exec -i "$name" tar -x -C /opt/savana-baseline
docker exec "$name" sh -c 'rm -rf /opt/savana-baseline/experiments/results
  chown -R root:root /opt/savana-baseline && chmod -R a+rX,go-w /opt/savana-baseline
  chown savana-experiment:savana-experiment /opt/savana-baseline-results && chmod 0700 /opt/savana-baseline-results'
echo "$name ready: runner from $(git -C "$repo" rev-parse --short HEAD)"
