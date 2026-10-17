# Test node for meshly integration tests: a plain Linux userland with the
# tools meshly needs (nft, ip) plus test helpers. Runs in its own network
# namespace; nothing touches the host firewall.
ARG BASE=debian:12
FROM ${BASE}
RUN apt-get update -qq \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends \
      nftables iptables iproute2 wireguard-tools conntrack netcat-openbsd iputils-ping procps ca-certificates \
 && rm -rf /var/lib/apt/lists/*
CMD ["sleep", "infinity"]
