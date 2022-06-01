#!/usr/bin/env bash

# Improvement: rewrite in actual programming language ..... :( time constraints
# Improvement: timestamps in all output messages, use `logger` (if we keep using bash)


full_path=$(realpath $0)
dir_path=$(dirname $full_path)

# Note: on a 2 core VM on my iMac, I can process about 30 items/second (1373 items in IP registry took 45 seconds)
# as it stands, something like a SYN flood will overwhelm the queue

# Fetch number of seconds since boot once at the beginning
ktime_current=$(cat /proc/uptime | awk '{ print $1}')
# Setup cutoff time to be 60 seconds in the past from now
# items with timestamp less than cutoff time will be expired
ktime_cutoff=$(echo "${ktime_current} - 60" | bc)
echo "Starting expiration of Portscan IP registry at ${ktime_current} with cutoff ${ktime_cutoff}"

# Improvement: flock, or other way of prevent multiple instances of this from running?

# Iterating with get_nextkey is tricky ... when we get an error, retry? abort?
# what if we are flooded with portscans and keys keep coming

# Get keys of items in the registry
# Fetches the HEX formatted keys like this
# "key": [
#    "0x7f",
#    "0x00",
#    "0x00",
#    "0x60"
# ],
# and translates it into HEX string like this
# 0x7f 0x00 0x00 0x5f
current_registry_keys_hex=$(bpftool map dump name pscan_ip_reg -p | jq -r '.[] | (.key | join(" "))')
# Exit if the registry is empty
if [ -z "${current_registry_keys_hex}" ]; then
  echo "Empty Portscan IP registry, exiting"
  exit 0
fi

# Iterate over items in IP registry
echo "${current_registry_keys_hex}" | parallel -j+32 "${dir_path}/portscan_process_entry.sh {} '${ktime_cutoff}'"

# Shortcut: this makes the count imprecise, but it should be "accurate" within a intervals of this script runs
# we could decrement by total of expirations, but:
# - bpftool does not support BPF_F_LOCK map update (yet), would end up with imprecise counter anyways
# - would require redesign of data structure in pscan_stats (time constraints)

# Update the IP registry size to the map size after expiration of items
current_registry_count=$(bpftool map lookup name pscan_stats key 6 | jq -r '.value')
final_registry_items_count=$(bpftool map dump name pscan_ip_reg | jq -r '.[] | .key' | wc -l)
# Translates
# 18
# into
# 18 00 00 00 00 00 00 00
#
# Internally, in the map, '11' would be stored as
# "0x18","0x00","0x00","0x00","0x00","0x00","0x00","0x00"
bpftool_formatted_count=$(printf '%016x\n' ${final_registry_items_count} | fold -w2  | tac | tr '\n' ' ')
echo "Current registry size in the stats map: ${current_registry_count}"
if [ $current_registry_count -ne $final_registry_items_count ]; then
  echo "Updating the IP registry size in stats map to be ${final_registry_items_count}, bpftool value ${bpftool_formatted_count}"
  set -x
  # 6 is an ID of STAT_REGISTRY_SIZE, see `enum our_stats`
  bpftool map update name pscan_stats key 6 value hex ${bpftool_formatted_count}
  set +x
  echo "Updated registry size in the stats map: $(bpftool map lookup name pscan_stats key 6 | jq -r '.value')"
fi

echo "Finished expiration of Portscan IP registry at $(cat /proc/uptime | awk '{ print $1}')"
echo "----"
echo ""