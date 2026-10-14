# A stand-in for a brand-new machine reached over SSH: Ubuntu 24.04 with
# systemd and sshd (127.0.0.1:2222, keys only; create.sh starts it once it has
# made the host key), and nothing of the experiment's runtime, which
# `savana_lab.remote` installs on it as on any new machine. certs/ holds this
# machine's extra CA certificates (its egress proxy), as for hostimg/; it may
# be empty.
FROM mirror.gcr.io/library/ubuntu:24.04
COPY certs/ /usr/local/share/ca-certificates/
RUN if ls /usr/local/share/ca-certificates/*.crt >/dev/null 2>&1; then \
      sed -i 's#http://#https://#g' /etc/apt/sources.list.d/ubuntu.sources \
      && cat /usr/local/share/ca-certificates/*.crt > /etc/apt/session-egress.pem \
      && printf 'Acquire::https::CAInfo "/etc/apt/session-egress.pem";\n' > /etc/apt/apt.conf.d/99session-ca; \
    fi \
 && apt-get update -q && DEBIAN_FRONTEND=noninteractive apt-get install -y -q --no-install-recommends \
    systemd systemd-sysv dbus openssh-server sudo ca-certificates \
 && rm -rf /var/lib/apt/lists/* && update-ca-certificates >/dev/null \
 && (systemctl mask systemd-logind.service getty.target console-getty.service systemd-udevd.service systemd-udev-trigger.service systemd-networkd.service systemd-resolved.service systemd-timesyncd.service 2>/dev/null || true) \
 && rm -f /etc/ssh/ssh_host_* && systemctl disable ssh.socket ssh.service \
 && printf 'Port 2222\nListenAddress 127.0.0.1\nPasswordAuthentication no\nKbdInteractiveAuthentication no\nPermitRootLogin prohibit-password\n' > /etc/ssh/sshd_config.d/savana-lab.conf
STOPSIGNAL SIGRTMIN+3
CMD ["/usr/lib/systemd/systemd"]
