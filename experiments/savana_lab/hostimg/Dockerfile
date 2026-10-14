# The disposable host every batch runs on: Ubuntu 24.04 with systemd as PID 1
# and the pinned AgentDojo venv the installer seals (/opt/savana-bench-venv).
# certs/ holds the build machine's extra CA certificates (its egress proxy),
# copied in by `savana_lab.host.DockerHost.ensure_image`; it may be empty.
FROM mirror.gcr.io/library/ubuntu:24.04
COPY certs/ /usr/local/share/ca-certificates/
RUN if ls /usr/local/share/ca-certificates/*.crt >/dev/null 2>&1; then \
      sed -i 's#http://#https://#g' /etc/apt/sources.list.d/ubuntu.sources \
      && cat /usr/local/share/ca-certificates/*.crt > /etc/apt/session-egress.pem \
      && printf 'Acquire::https::CAInfo "/etc/apt/session-egress.pem";\n' > /etc/apt/apt.conf.d/99session-ca; \
    fi \
 && apt-get update -q && DEBIAN_FRONTEND=noninteractive apt-get install -y -q --no-install-recommends \
    systemd systemd-sysv dbus python3 python3-venv python3-pip ca-certificates binutils acl iproute2 procps curl sudo less tcpdump strace acl \
 && rm -rf /var/lib/apt/lists/* && update-ca-certificates >/dev/null \
 && (systemctl mask systemd-logind.service getty.target console-getty.service systemd-udevd.service systemd-udev-trigger.service systemd-networkd.service systemd-resolved.service systemd-timesyncd.service 2>/dev/null || true)
COPY requirements-agentdojo.txt /root/requirements-agentdojo.txt
RUN python3 -m venv /opt/savana-bench-venv && /opt/savana-bench-venv/bin/pip install -q --no-cache-dir -r /root/requirements-agentdojo.txt
STOPSIGNAL SIGRTMIN+3
CMD ["/usr/lib/systemd/systemd"]
