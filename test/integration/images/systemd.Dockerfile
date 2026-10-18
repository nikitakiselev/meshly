# Test node with systemd as PID 1, for service/reboot/upgrade/install tests.
# A container restart stands in for a reboot: the network namespace (and
# with it the interface and every nftables table) is recreated empty.
# With --build-arg DOCKER=1 the node also has Docker CE (vfs storage),
# busybox-static and conntrack; Docker is not started at boot: tests start it
# themselves.
ARG BASE=debian:12
FROM ${BASE}
# UFW is installed but not enabled; the tests that need it turn it on.
RUN apt-get update -qq \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends \
      systemd systemd-sysv dbus nftables iptables ufw iproute2 wireguard-tools netcat-openbsd iputils-ping procps \
      ca-certificates openssl curl \
 && rm -rf /var/lib/apt/lists/* \
 && systemctl mask getty@tty1.service console-getty.service systemd-logind.service \
 && systemctl disable nftables.service || true
ARG DOCKER
RUN test -z "$DOCKER" || { . /etc/os-release \
 && install -m 0755 -d /etc/apt/keyrings /etc/docker \
 && curl -fsSL "https://download.docker.com/linux/$ID/gpg" -o /etc/apt/keyrings/docker.asc \
 && echo "deb [signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/$ID $VERSION_CODENAME stable" > /etc/apt/sources.list.d/docker.list \
 && apt-get update -qq \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends docker-ce docker-ce-cli containerd.io busybox-static conntrack \
 && rm -rf /var/lib/apt/lists/* \
 && echo '{"storage-driver":"vfs"}' > /etc/docker/daemon.json \
 && systemctl disable docker.service docker.socket containerd.service; }
# The lab's "DHCP": restore the default route recorded in /etc/it-gateway.
RUN printf '%s\n' '[Unit]' 'Before=network-pre.target meshly.service' 'Wants=network-pre.target' 'DefaultDependencies=no' \
      '[Service]' 'Type=oneshot' 'ExecStart=/bin/sh -c "test -s /etc/it-gateway && ip route replace default via $(cat /etc/it-gateway) || true"' \
      '[Install]' 'WantedBy=sysinit.target' > /etc/systemd/system/it-route.service \
 && systemctl enable it-route.service
STOPSIGNAL SIGRTMIN+3
CMD ["/sbin/init"]
