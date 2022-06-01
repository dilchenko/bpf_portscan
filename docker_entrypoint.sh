#!/usr/bin/env bash

#NET_IF_NAME=${1}
#BPF_O_PATH=${2}

APP_ROOT='/app/bpf_portscan'

_unload_xdp() {
  # Improvement: dump BPF maps into a file, they are lost xdp is unloaded and no other FDs hold them open
  cd ${APP_ROOT}
  make xdp_unload NET_IF_NAME=${NET_IF_NAME} BPF_O_PATH=${BPF_O_PATH}
}

_term() {
  echo "Caught SIGTERM signal"
  _unload_xdp
  kill -TERM "$child" 2>/dev/null
}

_kill() {
  echo "Caught SIGKILL signal"
  _unload_xdp
  kill -KILL "$child" 2>/dev/null
}

trap _term SIGTERM
trap _kill SIGKILL

# Improvement: load BPF maps from a file
cd ${APP_ROOT}
make xdp_unload NET_IF_NAME=${NET_IF_NAME} BPF_O_PATH=${BPF_O_PATH} # trap above does not work for some reason

# stats server
${APP_ROOT}/pscan_stats_linux &

child=$!
wait "$child"