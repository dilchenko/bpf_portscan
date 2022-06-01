#!/usr/bin/env bash

#set -x
registry_item_key="${1}"
ktime_cutoff="${2}"
echo "portscan entry expiry: registry_item_key: '${registry_item_key}'"
# Translate
# 0x7f 0x00 0x00 0x5f
# into
# 127 0 0 95
bpftool_formatted_key="$(for h in ${registry_item_key}; do printf '%d ' ${h}; done | sed 's/ $//')"

# skip if blocked IP
is_ip_blocked=$(bpftool map lookup name pscan_ip_reg key ${bpftool_formatted_key} | jq -r '.value | .blocked')
if [ "${is_ip_blocked}" == "1" ]; then
  echo "Skipping '${bpftool_formatted_key}' because it is blocked=${is_ip_blocked}"
  continue
fi

# fetch item timestamp, in nanoseconds
item_ts_ns=$(bpftool map lookup name pscan_ip_reg key ${bpftool_formatted_key} | jq -r '.value | .packet_timestamp')

# convert item timestamp into seconds with precision of 2
item_ts_sec=$(echo "scale=2; ${item_ts_ns} / 1000000000" | bc)

# Expire if timestamp if less that cutoff timestamp
if (( $(echo "${item_ts_sec} < ${ktime_cutoff}" |bc -l) )); then
  echo "Expiring '${bpftool_formatted_key}' with timestamp ${item_ts_sec}"
  # htab_map_delete_elem is protected by spin lock - see `static int htab_map_delete_elem` in `bpf/hashtab.c`
  set -x
  bpftool map delete name pscan_ip_reg key ${bpftool_formatted_key} -d
  set +x
else
  echo "Skipping '${bpftool_formatted_key}' because newer than cutoff ts=${item_ts_sec}"
fi
#set +x