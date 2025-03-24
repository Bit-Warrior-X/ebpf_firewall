// xdp_prog.c
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

/* Tail call map: keys will be used to jump to parse functions.
 * Key 0 -> xdp_parse_syn, Key 1 -> xdp_parse_ack.
 */
struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(max_entries, 2);
    __type(key, __u32);
    __type(value, __u32);
} prog_array SEC(".maps");

/* LRU hash map to record source IP addresses for SYN packets.
 * The key is the source IP (in network byte order)
 * The value is a counter (number of SYN packets seen).
 */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);
    __type(value, __u64);
} syn_ips_map SEC(".maps");

//
// xdp_main: entry point for the XDP program.
//
SEC("xdp")
int xdp_main(struct xdp_md *ctx) {
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    
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
    
    if (bpf_htons(tcph->dest) != 80)
        return XDP_PASS;

    // Check TCP flags:
    // If SYN flag is set and ACK flag is not set, then it's a SYN packet.
    if (tcph->syn && !tcph->ack) {
        // Tail call to xdp_parse_syn (map key 0).
        bpf_tail_call(ctx, &prog_array, 0);
    }
    // If ACK flag is set, then it is treated as an ACK packet.
    else if (tcph->ack) {
        // Tail call to xdp_parse_ack (map key 1).
        bpf_tail_call(ctx, &prog_array, 1);
    }
    
    // If tail call fails or packet does not match above criteria,
    // then pass the packet.
    return XDP_PASS;
}

//
// xdp_parse_syn: processes SYN packets.
// It records the source IP address in an LRU hash map.
//
SEC("xdp")
int xdp_parse_syn(struct xdp_md *ctx) {
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    
    struct ethhdr *eth = data;
    if ((void*)(eth + 1) > data_end)
        return XDP_PASS;
    
    if (eth->h_proto != __constant_htons(ETH_P_IP))
        return XDP_PASS;
    
    struct iphdr *iph = data + sizeof(*eth);
    if ((void*)(iph + 1) > data_end)
        return XDP_PASS;
    
    
    // Parse TCP header.
    struct tcphdr *tcp = (void *)iph + sizeof(*iph);
    if ((void*)(tcp + 1) > data_end)
        return XDP_PASS;

    // Get source IP address.
    __u32 src_ip = iph->saddr;
    __u32 dst_ip = iph->daddr;
    __u64 init_val = 1;
    __u64 *count;
    
    bpf_printk("SYN packet for %pI4-----> %pI4 is filtered and sent to service", &src_ip,&dst_ip);

    // Look up the source IP in the LRU hash map.
    count = bpf_map_lookup_elem(&syn_ips_map, &src_ip);
    if (count) {
        // Increment the counter.
        __u64 new_count = *count + 1;
        bpf_map_update_elem(&syn_ips_map, &src_ip, &new_count, BPF_EXIST);
        bpf_printk("syn packets for ip is %lu\n", new_count);
    } else {
        // Insert the source IP with initial count.
        bpf_map_update_elem(&syn_ips_map, &src_ip, &init_val, BPF_ANY);
        bpf_printk("syn packets for ip is %lu\n", init_val);
    }

    return XDP_PASS;
}

//
// xdp_parse_ack: processes ACK packets.
// It checks if the source IP address is in the syn_ips_map.
// If present, the packet is passed; otherwise, it is dropped.
//
SEC("xdp")
int xdp_parse_ack(struct xdp_md *ctx) {
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    
    struct ethhdr *eth = data;
    if ((void*)(eth + 1) > data_end)
        return XDP_DROP;
    
    if (eth->h_proto != __constant_htons(ETH_P_IP))
        return XDP_DROP;
    
    struct iphdr *iph = data + sizeof(*eth);
    if ((void*)(iph + 1) > data_end)
        return XDP_DROP;
    
    
    // Parse TCP header.
    struct tcphdr *tcp = (void *)iph + sizeof(*iph);
    if ((void*)(tcp + 1) > data_end)
        return XDP_PASS;

    __u32 src_ip = iph->saddr;
    __u32 dst_ip = iph->daddr;
    
    __u64 *count = bpf_map_lookup_elem(&syn_ips_map, &src_ip);
    if (count) {
        bpf_printk("ACK packet for %pI4 -----> %pI4 is exist so pass", &src_ip, &dst_ip);
        bpf_printk("Saved packets for ip is %lu\n", *count);
        return XDP_PASS;
    } else {
        bpf_printk("ACK packet for %pI4 -----> %pI4 is not exist !!!! \n", &src_ip, &dst_ip);
        return XDP_DROP;
    }
}

char _license[] SEC("license") = "GPL";
