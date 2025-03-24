// xdp_prog.c
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>


// Define time constants (in nanoseconds)
#define ONE_SECOND_NS      1000000000ULL
#define SIXTEEN_SECONDS_NS (16ULL * 1000000000ULL)
#define BLOCK_DURATION_NS  (3600ULL * 1000000000ULL)  // 1 hour
#define CHALLENGE_TIMEOUT_NS (2ULL * ONE_SECOND_NS)    // Timeout for challenge state

// Thresholds: Adjust these as required.
#define PPS_THRESHOLD    10000  // Maximum SYN packets per second allowed.
#define FIXED_THRESHOLD  50000  // Maximum SYN packets allowed in a 16-second window.

/* Tail call map: keys will be used to jump to parse functions.
 * Key 0 -> xdp_parse_syn, Key 1 -> xdp_parse_ack.
 */
struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(max_entries, 2);
    __type(key, __u32);
    __type(value, __u32);
} prog_array SEC(".maps");

// Existing counters for flood detection.
struct syn_stats {
    __u64 count;
    __u64 last_ts;
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65535);
    __type(key, __u32);             // Source IP address.
    __type(value, struct syn_stats);
} syn_counter_1s SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65535);
    __type(key, __u32);             // Source IP address.
    __type(value, struct syn_stats);
} syn_counter_16s SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65535);
    __type(key, __u32);             // Source IP address.
    __type(value, __u64);           // Block expiration time (ns)
} blocked_ips SEC(".maps");

// New structure and map for the SYN challenge state.
struct challenge_state {
    __u8 stage;       // 1: first SYN seen; 2: challenge sent (waiting for client response)
    __u64 ts;         // Timestamp when state was updated
    __u32 seq;        // Seq Number of syn
    __u32 wrong_seq;  // An arbitrary “wrong” sequence number to send in our challenge SYN+ACK.
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 1000000);
    __type(key, __u32);             // Source IP address.
    __type(value, struct challenge_state);
} syn_challenge SEC(".maps");

/* LRU hash map to record source IP addresses for SYN packets.
 * The key is the source IP (in network byte order)
 * The value is a counter (number of SYN packets seen).
 */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 100000);
    __type(key, __u32);   // Source IP address.
    __type(value, __u8);  // Temp value.
} syn_allowed_ips SEC(".maps");



static __always_inline __u16
csum_fold_helper(__u64 csum)
{
    int i;
    for (i = 0; i < 4; i++)
    {
        if (csum >> 16)
            csum = (csum & 0xffff) + (csum >> 16);
    }
    return ~csum;
}

static __always_inline __u16
iph_csum(struct iphdr *iph)
{
    iph->check = 0;
    unsigned long long csum = bpf_csum_diff(0, 0, (unsigned int *)iph, sizeof(struct iphdr), 0);
    return csum_fold_helper(csum);
}

SEC("xdp")
int xdp_main(struct xdp_md *ctx) {
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    __u64 now = bpf_ktime_get_ns();
    
    // Parse Ethernet header.
    struct ethhdr *eth = data;
    if ((void*)(eth + 1) > data_end)
        return XDP_PASS;
    
    // Only handle IP packets.
    if (eth->h_proto != __constant_htons(ETH_P_IP))
        return XDP_PASS;
    
    // Parse IP header.
    struct iphdr *iph = data + sizeof(*eth);
    if ((void*)(iph + 1) > data_end)
        return XDP_PASS;
    
    // Only handle TCP packets.
    if (iph->protocol != IPPROTO_TCP)
        return XDP_PASS;
    
    // Calculate IP header length.
    int ip_hdr_len = iph->ihl * 4;
    struct tcphdr *tcph = (void *)iph + ip_hdr_len;
    if ((void*)(tcph + 1) > data_end)
        return XDP_PASS;
    
    // For test purpose, we use only 80 port in firewall
    if (bpf_htons(tcph->dest) != 80)
        return XDP_PASS;

    // Check if the IP is already blocked.
    __u32 src_ip = iph->saddr;
    __u64 *blocked_exp = bpf_map_lookup_elem(&blocked_ips, &src_ip);
    if (blocked_exp) {
        if (now < *blocked_exp)
            return XDP_DROP;
        else {
            bpf_printk("IP %pI4 removed from block list\n", &src_ip);
            bpf_map_delete_elem(&blocked_ips, &src_ip);
        }
    }

    // Check TCP flags:
    // If SYN flag is set and ACK flag is not set, then it's a SYN packet.
    if (tcph->syn && !tcph->ack) {
        // Tail call to xdp_parse_syn (map key 0).
        bpf_tail_call(ctx, &prog_array, 0);
    }
    // If ACK or RST flag is set, then it is treated as an ACK packet.
    else if (tcph->ack || tcph->rst) {
        // Tail call to xdp_parse_ack (map key 1).
        bpf_tail_call(ctx, &prog_array, 1);
    }
    
    // If tail call fails or packet does not match above criteria,
    // then pass the packet.
    return XDP_PASS;
}

SEC("xdp")
int xdp_parse_syn(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    __u64 now = bpf_ktime_get_ns();

    // Parse Ethernet header.
    struct ethhdr *eth = data;
    if ((void*)(eth + 1) > data_end)
        return XDP_PASS;
    if (eth->h_proto != __constant_htons(ETH_P_IP))
        return XDP_PASS;

    // Parse IP header.
    struct iphdr *ip = data + sizeof(*eth);
    if ((void*)(ip + 1) > data_end)
        return XDP_PASS;
    if (ip->protocol != IPPROTO_TCP)
        return XDP_PASS;

    // Parse TCP header.
    struct tcphdr *tcp = (void *)ip + sizeof(*ip);
    if ((void*)(tcp + 1) > data_end)
        return XDP_PASS;

    // Get the source IP address.
    __u32 src_ip = ip->saddr;
    __u32 dst_ip = ip->daddr;
    
    // Process only TCP SYN packets (SYN set, ACK not set).
    if (tcp->syn && !tcp->ack) {
        //bpf_printk("%pI4:%d -----> %pI4:%d\n", &src_ip, bpf_htons(tcp->source), &dst_ip, bpf_htons(tcp->dest));
        // Check challenge state for this source IP.
        struct challenge_state *cstate = bpf_map_lookup_elem(&syn_challenge, &src_ip);
        if (cstate) {
            // If the state is too old, remove it.
            if (now - cstate->ts > CHALLENGE_TIMEOUT_NS) {
                // We have to determine if it is retransmission TCP SYN
                if (cstate->seq != tcp->seq) { 
                    //bpf_printk("  IP %pI4 is too old(%llu) and the syn is different\n", &src_ip, (now - cstate->ts) / 1000000000);        
                    bpf_map_delete_elem(&syn_challenge, &src_ip);
                    cstate = NULL;
                }
            }
        }

        if (cstate == NULL) {
            // First SYN from this IP:
            struct challenge_state new_state = {
                .stage = 1,
                .ts = now,
                .seq = tcp->seq,
                .wrong_seq = 0xdeadbeef  // Arbitrary wrong sequence number.
            };
            int result = bpf_map_update_elem(&syn_challenge, &src_ip, &new_state, BPF_ANY);
            // Drop the packet so that only retransmissions trigger further processing.
            //bpf_printk("  cstate is NULL and add it into syn challenge with %d\n", result);
            return XDP_DROP;

        } else if (cstate->stage == 1) {
            // Swap MAC addresses
            unsigned char tmp_mac[ETH_ALEN];
            __builtin_memcpy(tmp_mac, eth->h_source, ETH_ALEN);
            __builtin_memcpy(eth->h_source, eth->h_dest, ETH_ALEN);
            __builtin_memcpy(eth->h_dest, tmp_mac, ETH_ALEN);

            // Swap IP addresses
            __be32 tmp_ip = ip->saddr;
            ip->saddr = ip->daddr;
            ip->daddr = tmp_ip;

            // Swap TCP ports
            __be16 tmp_port = tcp->source;
            tcp->source = tcp->dest;
            tcp->dest = tmp_port;

            // Set SYN-ACK flags
            tcp->ack = 1;
            tcp->ack_seq = bpf_htonl(bpf_ntohl(tcp->seq) + 1);
            tcp->seq = bpf_htonl(0x1234); // Initial sequence number for the response

            ip->check = iph_csum(ip);

            // Update challenge state.
            cstate->stage = 2;
            cstate->ts = now;

            //bpf_printk("  Sent challenge SYN+ACK to %pI4 (ack_seq is %x, tcp->seq is %x, window is %x)\n",
            //        &src_ip, tcp->ack_seq, tcp->seq, tcp->window);
            return XDP_TX;
        }
        else if (cstate->stage == 2) {
            // This is the client's follow-up SYN in response to our challenge.
            // Remove the challenge state and allow the packet to be processed normally.
            bpf_map_delete_elem(&syn_challenge, &src_ip);
            //bpf_printk("  Challenge passed for %pI4\n", &src_ip);
            // (Fall through to the SYN flood detection logic.)
        }
    }

    // ----- Existing SYN flood detection counters -----
    if (tcp->syn && !tcp->ack) {
        // Process the 1-second counter.
        struct syn_stats *stats1 = bpf_map_lookup_elem(&syn_counter_1s, &src_ip);
        if (stats1) {
            if (now - stats1->last_ts > ONE_SECOND_NS) {
                stats1->count = 1;
                stats1->last_ts = now;
            } else {
                stats1->count += 1;
            }
        } else {
            struct syn_stats new_stats = { .count = 1, .last_ts = now };
            bpf_map_update_elem(&syn_counter_1s, &src_ip, &new_stats, BPF_ANY);
        }

        // Process the 16-second counter.
        struct syn_stats *stats16 = bpf_map_lookup_elem(&syn_counter_16s, &src_ip);
        if (stats16) {
            if (now - stats16->last_ts > SIXTEEN_SECONDS_NS) {
                stats16->count = 1;
                stats16->last_ts = now;
            } else {
                stats16->count += 1;
            }
        } else {
            struct syn_stats new_stats = { .count = 1, .last_ts = now };
            bpf_map_update_elem(&syn_counter_16s, &src_ip, &new_stats, BPF_ANY);
        }

        // Check if either threshold is exceeded.
        if (stats1 && stats1->count > PPS_THRESHOLD) {
            __u64 block_exp = now + BLOCK_DURATION_NS;
            bpf_map_update_elem(&blocked_ips, &src_ip, &block_exp, BPF_ANY);
            bpf_printk("[SYN] IP %pI4 blocked for per-second threshold\n", &src_ip);
            return XDP_DROP;
        }
        if (stats16 && stats16->count > FIXED_THRESHOLD) {
            __u64 block_exp = now + BLOCK_DURATION_NS;
            bpf_map_update_elem(&blocked_ips, &src_ip, &block_exp, BPF_ANY);
            bpf_printk("[SYN] IP %pI4 blocked for 16-second threshold\n", &src_ip);
            return XDP_DROP;
        }

        bpf_printk("[SYN] packet for %pI4:%d -----> %pI4:%d is filtered\n", &src_ip, bpf_htons(tcp->source), &dst_ip, bpf_htons(tcp->dest));

        __u8 temp_value = 1;
        bpf_map_update_elem(&syn_allowed_ips, &src_ip, &temp_value, BPF_ANY);
    }
    // --------------------------------------------------

    // Allow other packets (or non-SYN packets) to pass.
    return XDP_PASS;
}


// Thresholds: adjust these values as needed.
#define ACK_PPS_THRESHOLD 20000    // Maximum ACK/RST packets per second allowed.
#define ACK_FIXED_THRESHOLD 100000 // Maximum ACK/RST packets allowed in a 16-second window.


// Counters for ACK/RST flood detection.
struct ack_stats {
    __u64 count;
    __u64 last_ts;
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 100000);
    __type(key, __u32);    // Source IP address.
    __type(value, struct ack_stats);
} ack_counter_1s SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 100000);
    __type(key, __u32);    // Source IP address.
    __type(value, struct ack_stats);
} ack_counter_16s SEC(".maps");

SEC("xdp")
int xdp_parse_ack_rst(struct xdp_md *ctx) {
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    __u64 now = bpf_ktime_get_ns();
    
    struct ethhdr *eth = data;
    if ((void*)(eth + 1) > data_end)
        return XDP_DROP;
    
    if (eth->h_proto != __constant_htons(ETH_P_IP))
        return XDP_DROP;
    
    struct iphdr *iph = data + sizeof(*eth);
    if ((void*)(iph + 1) > data_end)
        return XDP_DROP;
    
    struct tcphdr *tcp = (void *)iph + sizeof(*iph);
    if ((void*)(tcp + 1) > data_end)
        return XDP_PASS;

    __u32 src_ip = iph->saddr;
    __u32 dst_ip = iph->daddr;
    
    // Process only packets with ACK or RST flag set.
    if (tcp->ack || tcp->rst) {
        __u8 *temp_value = bpf_map_lookup_elem(&syn_allowed_ips, &src_ip);
        if (temp_value == NULL) {  // Not added in syn challenge
            return XDP_DROP;
        }

        // Update 1-second counter.
        struct ack_stats *stats1 = bpf_map_lookup_elem(&ack_counter_1s, &src_ip);
        if (stats1) {
            if (now - stats1->last_ts > ONE_SECOND_NS) {
                stats1->count = 1;
                stats1->last_ts = now;
            } else {
                stats1->count += 1;
            }
        } else {
            struct ack_stats new_stats = { .count = 1, .last_ts = now };
            bpf_map_update_elem(&ack_counter_1s, &src_ip, &new_stats, BPF_ANY);
        }

        // Update 16-second counter.
        struct ack_stats *stats16 = bpf_map_lookup_elem(&ack_counter_16s, &src_ip);
        if (stats16) {
            if (now - stats16->last_ts > SIXTEEN_SECONDS_NS) {
                stats16->count = 1;
                stats16->last_ts = now;
            } else {
                stats16->count += 1;
            }
        } else {
            struct ack_stats new_stats = { .count = 1, .last_ts = now };
            bpf_map_update_elem(&ack_counter_16s, &src_ip, &new_stats, BPF_ANY);
        }

        // If either threshold is exceeded, block the IP for one hour.
        if (stats1 && stats1->count > ACK_PPS_THRESHOLD) {
            __u64 block_exp_time = now + BLOCK_DURATION_NS;
            bpf_map_update_elem(&blocked_ips, &src_ip, &block_exp_time, BPF_ANY);
            bpf_printk("[ACK] %pI4:%d is added into blocked_ips with stats1\n", &src_ip, bpf_htons(tcp->source));
            return XDP_DROP;
        }
        if (stats16 && stats16->count > ACK_FIXED_THRESHOLD) {
            __u64 block_exp_time = now + BLOCK_DURATION_NS;
            bpf_map_update_elem(&blocked_ips, &src_ip, &block_exp_time, BPF_ANY);
            bpf_printk("[ACK] %pI4:%d is added into blocked_ips with stats16\n", &src_ip, bpf_htons(tcp->source));
            return XDP_DROP;
        }
    }

    bpf_printk("[ACK] packet for %pI4:%d -----> %pI4:%d is filtered\n", &src_ip, bpf_htons(tcp->source), &dst_ip, bpf_htons(tcp->dest));

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
