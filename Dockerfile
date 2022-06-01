FROM ubuntu:jammy@sha256:26c68657ccce2cb0a31b330cb0be2b5e108d467f641c62e13ab40cbec258c68d

ARG override_dns
RUN if [ -n "$arg" ]; then echo '192.168.1.1' > /etc/resolv.conf; fi

ENV DEBIAN_FRONTEND noninteractive
RUN apt-get -q update
RUN apt-get -qy install apt-utils
RUN apt-get -qy install iproute2 make
# Potential improvement: determine kernel version dynamically
# Technically, we don't *need* bpftool (which comes from linux-tools*) within the container
RUN apt-get install -qy linux-tools-common linux-tools-5.15.0-33-generic
RUN mkdir -p /app/bpf_portscan/config
COPY bpf_kern_block.o /app/bpf_portscan/
COPY Makefile /app/bpf_portscan/
COPY docker_entrypoint.sh /app/bpf_portscan/
COPY bin/pscan_stats_linux /app/bpf_portscan/
COPY config/config.yml /app/bpf_portscan/config/
RUN chmod +x /app/bpf_portscan/docker_entrypoint.sh
CMD ["/app/bpf_portscan/docker_entrypoint.sh"]
EXPOSE 7979