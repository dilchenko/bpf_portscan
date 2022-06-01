FROM ubuntu:jammy@sha256:26c68657ccce2cb0a31b330cb0be2b5e108d467f641c62e13ab40cbec258c68d

ARG override_dns
RUN if [ -n "$arg" ]; then echo '192.168.1.1' > /etc/resolv.conf; fi

ENV DEBIAN_FRONTEND noninteractive
RUN apt-get -q update
RUN apt-get -qy install apt-utils iproute2 make
# Potential improvement: determine kernel version dynamically
# Technically, we don't *need* bpftool (which comes from linux-tools*) within the container
# right now, required for IP registry expiration job
RUN apt-get install -qy linux-tools-common linux-tools-5.15.0-33-generic

# App directory
RUN mkdir -p /app/bpf_portscan/config

# Shortcut: no need for cron once expiration is reimplemented in Go
# Other requirements for IP registry expiration job
RUN apt-get install -qy jq parallel coreutils bc cron
RUN rm -rf /etc/cron.daily/*
RUN rm -rf /etc/cron.monthy/*
RUN rm -rf /etc/cron.weekly/*\
RUN rm -rf /etc/cron.d/*

COPY portscan_expire_registry.sh /app/bpf_portscan/
COPY portscan_process_entry.sh /app/bpf_portscan/
RUN chmod +x /app/bpf_portscan/portscan_expire_registry.sh
RUN chmod +x /app/bpf_portscan/portscan_process_entry.sh
COPY portscan_expire_registry.cron /etc/cron.d/
RUN chmod 0644 /etc/cron.d/portscan_expire_registry.cron
RUN crontab /etc/cron.d/portscan_expire_registry.cron
RUN touch /var/log/cron.log

COPY bpf_kern_block.o /app/bpf_portscan/
COPY Makefile /app/bpf_portscan/
COPY docker_entrypoint.sh /app/bpf_portscan/
COPY bin/pscan_stats_linux /app/bpf_portscan/
COPY config/config.yml /app/bpf_portscan/config/

RUN chmod +x /app/bpf_portscan/docker_entrypoint.sh

# Cleanup
RUN apt-get clean autoclean
RUN apt-get autoremove --yes
RUN rm -rf /var/lib/cache,log,lists}/

CMD ["/app/bpf_portscan/docker_entrypoint.sh"]
EXPOSE 7979