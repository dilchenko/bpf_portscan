//
// Created by Dima on 5/26/22.
//

#include <uapi/linux/bpf.h>
#include <uapi/linux/if_ether.h>
#include <uapi/linux/ip.h>
#include <uapi/linux/tcp.h>
#include "bpf_helpers.h"

#define IP_ADDR_MAP_SIZE 1000000

/*
 * enum xdp_action {
	XDP_ABORTED =                          0,
	XDP_DROP,                              1
	XDP_PASS,                              2
	XDP_TX,                                3
	XDP_REDIRECT,                          4
}; */
enum our_stats {
    STAT_CONN_NEW     = XDP_REDIRECT+1, // 5
    STAT_REGISTRY_SIZE,                 // 6
};

struct IpInfo {
    struct bpf_spin_lock bpf_lock;
    u8 blocked;  // cannot use `bool` because `bpftool map` returns true for bool regardless of actual value
    u64 packet_timestamp;
    u32 port1; /* Ideally, use an array, but interacting with an array gets even more complex */
    u32 port2;
    u32 port3;
};

// Map definitions with BTF to make spinlocks work and nice btftool dump
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u32);
    __type(value, struct IpInfo);
    __uint(max_entries, IP_ADDR_MAP_SIZE);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} pscan_ip_reg SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u8);
    __type(value, u64);
    __uint(max_entries, (STAT_REGISTRY_SIZE + 1));
} pscan_stats SEC(".maps");

#ifdef  DEBUG
/* Debug output can be accessed in /sys/kernel/debug/tracing/trace_pipe
 * See https://events.static.linuxfound.org/sites/events/files/slides/praesentation_0.pdf
 */
#define bpf_log_trace(format, ...)	\
		({							\
			char ____format[] = format;				\
			bpf_trace_printk(____format, sizeof(____format), ##__VA_ARGS__);			\
		})
#else
#define bpf_log_trace(format, ...) { } while (0)
#endif

// Possible improvement: utilize kernel atomic_* ops
// https://www.hitchhikersguidetolearning.com/2021/01/03/linux-kernel-atomic-operations/
#ifndef lock_xadd
#define lock_xadd(ptr, val)	((void) __sync_fetch_and_add(ptr, val))
#endif

/* Keeps stats of XDP_DROP vs XDP_PASS */
static __always_inline
int stats_map_increment(u8 stats_map_key, u8 increment) {
    if (stats_map_key > STAT_REGISTRY_SIZE)
        return -1;
    u64 * stats_map_value = bpf_map_lookup_elem(&pscan_stats, &stats_map_key);
    if (!stats_map_value) {
        u64 init_value = 0;
        bpf_map_update_elem(&pscan_stats, &stats_map_key, &init_value, BPF_NOEXIST); // Only update if element did not exist
    }
    // Entry for map_key should exist by now
    stats_map_value = bpf_map_lookup_elem(&pscan_stats, &stats_map_key);
    if (!stats_map_value)
        return stats_map_key; // something is wrong with the stats map, so just return
    lock_xadd(stats_map_value, (u64)1);
    return stats_map_key;
}

static __always_inline
int blocked_ip_info(u32 *ip_src_addr, u32 port1, u32 port2, u32 port3) {
    bpf_log_trace("[BLOCKED] xdp_port_scan_block: %pI4, ", ip_src_addr);
    bpf_log_trace("[BLOCKED] xdp_port_scan_block: ports:[%u,%u,%u]", port1, port2, port3);
    return stats_map_increment(XDP_DROP, 1);
}

static __always_inline
u64 ip_registry_size() {
    u8 stats_map_key = STAT_REGISTRY_SIZE;
    u64 * stats_map_value = bpf_map_lookup_elem(&pscan_stats, &stats_map_key);
    if (!stats_map_value) {
        u64 init_value = 0;
        bpf_log_trace("[DEBUG] xdp_port_scan_block: init ip registry size with initial size %u", init_value);
        bpf_map_update_elem(&pscan_stats, &stats_map_key, &init_value, BPF_NOEXIST); // Only update if element did not exist
    }
    // Entry for map_key should exist by now
    stats_map_value = bpf_map_lookup_elem(&pscan_stats, &stats_map_key);
    if (!stats_map_value)
        return 0; // something is wrong with the stats map, so just return 0
    bpf_log_trace("[DEBUG] xdp_port_scan_block: ip registry size:%u", *stats_map_value);
    return *stats_map_value;
}

// Possible improvement: abstract offset checker into a function - kernel BPF verifier seems to be unhappy about that
static __always_inline
u16 parse_ethernet_proto(struct ethhdr *ethernet_header, void *xdp_data_end) {
    u64 expected_eth_offset = sizeof(*ethernet_header);
    if ( (void *)ethernet_header + expected_eth_offset > xdp_data_end) {
        bpf_log_trace("[ERROR] xdp_port_scan_block: ETH header wrong size: xdp_data_end:%lu expected_end:%lu", \
                        xdp_data_end, (void *)ethernet_header + expected_eth_offset);
        return stats_map_increment(XDP_ABORTED,1);
    };
    return ntohs(ethernet_header->h_proto);
}

static __always_inline
u32 parse_ip_src_addr(struct iphdr *ip_header, void *xdp_data_end) {
    u64 expected_ip_offset = sizeof(*ip_header);
    if ((void *) ip_header + expected_ip_offset > xdp_data_end) {
        bpf_log_trace("[ERROR] xdp_port_scan_block: IP header wrong size: xdp_data_end:%lu expected_end:%lu", \
                      xdp_data_end, (void *) ip_header + expected_ip_offset);
        return stats_map_increment(XDP_ABORTED, 1);
    }
    return ip_header->saddr;
}

static __always_inline
u32 parse_tcp_dport(struct tcphdr *tcp_header, void *xdp_data_end) {
    u64 expected_tcp_offset = sizeof(*tcp_header);
    if ( (void *)tcp_header + expected_tcp_offset > xdp_data_end) {
        bpf_log_trace("[ERROR] xdp_port_scan_block: TCPv4 header wrong size: xdp_data_end:%lu expected_end:%lu",
                      xdp_data_end, (void *)tcp_header + expected_tcp_offset);
        return stats_map_increment(XDP_ABORTED,1);
    }
    // Increment new connection counter
    if (tcp_header->syn == 1 && tcp_header->ack == 0) {
        stats_map_increment(STAT_CONN_NEW,1);
    }
    // Possible improvement/consideration: verify TCP/IP checksums? defeats the purpose due to performance hit?
    return ntohs(tcp_header->dest);
}

SEC("xdp_port_scan_block")
int  xdp_port_scan_block_func(struct xdp_md *ctx)
{
    // No context? ... nothing to do?!
    if (!ctx) {
        bpf_log_trace("[ERROR] xdp_port_scan_block: empty context");
        return XDP_ABORTED;
    }

    // Check if we are already tracking max number of IP addrs in the registry; ABORT if we are
    // Possible improvement/consideration: instead of PASS, should we ABORT (and thus block) like conntrack?
    u64 ip_reg_size = ip_registry_size();
    if (ip_reg_size == IP_ADDR_MAP_SIZE) {
        bpf_log_trace("[ERROR] xdp_port_scan_block: tracking %u IP addresses which is > than max allowed %u", \
                        ip_reg_size, IP_ADDR_MAP_SIZE);
        return stats_map_increment(XDP_PASS,1);
    }

    // Get timestamp as close to the first log message
    u64 packet_timestamp = bpf_ktime_get_ns();

    // Obtain essential bits from the context
    void *xdp_data_end = (void *)(long)ctx->data_end;
    void *xdp_data     = (void *)(long)ctx->data;

    // Parse level 2 header, get Ethernet protocol
    struct ethhdr *ethernet_header = xdp_data;
    u16 ethernet_proto = parse_ethernet_proto(ethernet_header, xdp_data_end);
    if (ethernet_proto == XDP_ABORTED)
        return XDP_ABORTED;
    bpf_log_trace("[DEBUG] xdp_port_scan_block: eth_type:0x%x", ethernet_proto);
    /* Shortcut: do not handle VLAN encapsulated packets for now
     * Possible improvement: decapsulate VLAN packets.
     *  do we ever see VLAN tagged packets on the end hosts? if not, should we just drop VLAN protocols if encountered?
     * Shortcut: only handle IPv4 for now
     * Possible improvement: handle IPv6 - is it used in our network?
     */

    if (!(ethernet_proto == ETH_P_IP)) {
        // Possible improvement: hide this behind macro, it can be both useful and very chatty
        // bpf_log_trace("[DEBUG] xdp_port_scan_block: cannot handle proto:0x%x", ethernet_proto);
        return stats_map_increment(XDP_PASS,1);
    }
    bpf_log_trace("[DEBUG] xdp_port_scan_block: handling IPv4 proto proto:0x%x", ETH_P_IP);

    // Extract IPv4 source address from the IPv4 header
    struct iphdr *ip_header = (void *)ethernet_header + sizeof(*ethernet_header);
    u32 ip_src_addr = parse_ip_src_addr(ip_header, xdp_data_end);
    if (ip_src_addr == XDP_ABORTED)
        return XDP_ABORTED;
    bpf_log_trace("[DEBUG] xdp_port_scan_block: IPv4 source address:0x%x int%u %pI4", ip_src_addr, ip_src_addr, &ip_src_addr);

    // Parse TCPv4 header and obtain destination address
    struct tcphdr *tcp_header = (void *)ip_header + sizeof(*ip_header);
    u32 tcp_dport = parse_tcp_dport(tcp_header, xdp_data_end);
    if (tcp_dport==XDP_ABORTED)
        return XDP_ABORTED;
    bpf_log_trace("[DEBUG] xdp_port_scan_block: tcp_port:%u", tcp_dport);

    // Check this IP address is already in the registry
    struct IpInfo * exst_ip_inf = bpf_map_lookup_elem(&pscan_ip_reg, &ip_src_addr);
    bpf_log_trace("[DEBUG] xdp_port_scan_block: exst_ip_inf:%u", exst_ip_inf);
    // Initialize the info for a new ip address
    if (!exst_ip_inf) {
        // This is a new IP address
        struct bpf_spin_lock new_lock;
        struct IpInfo new_ip_info = {.packet_timestamp = packet_timestamp,
                                     .bpf_lock = new_lock,
                                     .blocked = 0,
                                     .port1 = tcp_dport, .port2 = 0, .port3 = 0};
        // Checking for err here makes the BPF kernel validator unhappy; could be edge case/bug
        bpf_map_update_elem(&pscan_ip_reg, &ip_src_addr, &new_ip_info, BPF_NOEXIST);
        // New entry in the IP registry - increment the registry size counter
        // Possible improvement: better error checking here, not clear what to do if error occurred
        stats_map_increment(STAT_REGISTRY_SIZE,1);
    }
    // IP Info should exist now, no matter what
    // The only case it would not is when map is full
    exst_ip_inf = bpf_map_lookup_elem(&pscan_ip_reg, &ip_src_addr);
    if (!exst_ip_inf) {
        return stats_map_increment(XDP_ABORTED, 1); // Something is wrong with IP registry
    } else {
        // An already blocked IP address
        if (exst_ip_inf->blocked) {
            bpf_log_trace("[DEBUG] xdp_port_scan_block: found an already blocked IP");
            return blocked_ip_info(&ip_src_addr, exst_ip_inf->port1, exst_ip_inf->port2, exst_ip_inf->port3);
        }
        bpf_log_trace("[DEBUG] xdp_port_scan_block: ports:[%u,%u,%u]",
                      exst_ip_inf->port1, exst_ip_inf->port2, exst_ip_inf->port3);
        // Improvement: what we really need here is per-cpu hashmap for registry
        // and a bit of math that would check that .port1-3 are present on each CPU
        // Lock the existing IP info element in the hash table
        bpf_spin_lock(&exst_ip_inf->bpf_lock);
        // "Main state machine" - update port timestamps and/or block if encountered 3 distinct ports
        if (exst_ip_inf->port1 == tcp_dport || exst_ip_inf->port2 == tcp_dport || exst_ip_inf->port3 == tcp_dport) {
            // Not a new port, update timestamp
            exst_ip_inf->packet_timestamp = packet_timestamp;
        } else if (!exst_ip_inf->port2) {
            // .port1 should always exist; if port 2 does not - add it, and PASS
            exst_ip_inf->packet_timestamp = packet_timestamp;
            exst_ip_inf->port2 = tcp_dport;
        } else if (!exst_ip_inf->port3) {
            // .port1 and .port2 are not empty, so this is the 3rd unique port => portscan detected
            exst_ip_inf->packet_timestamp = packet_timestamp;
            exst_ip_inf->port3 = tcp_dport;
            exst_ip_inf->blocked = 1;
            // Ensure the existing IP info element in the hash table is unlocked
            bpf_spin_unlock(&exst_ip_inf->bpf_lock);
            return blocked_ip_info(&ip_src_addr, exst_ip_inf->port1, exst_ip_inf->port2, exst_ip_inf->port3);
        }
        // Ensure the existing IP info element in the hash table is unlocked
        bpf_spin_unlock(&exst_ip_inf->bpf_lock);
    }
    return stats_map_increment(XDP_PASS,1);
}

char _license[] SEC("license") = "GPL";
