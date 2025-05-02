#include <ebpf_firewall_common.h>
#include <ebpf_firewall_log.h>


void print_firewall_status(struct tm * tm_info, int reason, __u32 srcip) {

    char src[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &srcip, src, sizeof(src));

    char buffer[26];
    strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", tm_info);

    // Print the timestamp only once at the beginning
    printf("%s    ", buffer);

    if (reason == EVENT_IP_BLOCK_END) {
        printf("EVENT_IP_BLOCK_END %s\n", src);
    } else if (reason == EVENT_TCP_SYN_ATTACK_PROTECION_MODE_START) {
        printf("EVENT_TCP_SYN_ATTACK_PROTECION_MODE_START\n");
    } else if (reason == EVENT_TCP_SYN_ATTACK_PROTECION_MODE_END) {
        printf("EVENT_TCP_SYN_ATTACK_PROTECION_MODE_END\n");
    } else if (reason == EVENT_TCP_SYN_ATTACK_BURST_BLOCK) {
        printf("EVENT_TCP_SYN_ATTACK_BURST_BLOCK %s\n", src);
    } else if (reason == EVENT_TCP_SYN_ATTACK_FIXED_BLOCK) {
        printf("EVENT_TCP_SYN_ATTACK_FIXED_BLOCK %s\n", src);
    }
    
    else if (reason == EVENT_TCP_ACK_ATTACK_PROTECION_MODE_START) {
        printf("EVENT_TCP_ACK_ATTACK_PROTECION_MODE_START\n");
    } else if (reason == EVENT_TCP_ACK_ATTACK_PROTECION_MODE_END) {
        printf("EVENT_TCP_ACK_ATTACK_PROTECION_MODE_END\n");
    } else if (reason == EVENT_TCP_ACK_ATTACK_BURST_BLOCK) {
        printf("EVENT_TCP_ACK_ATTACK_BURST_BLOCK %s\n", src);
    } else if (reason == EVENT_TCP_ACK_ATTACK_FIXED_BLOCK) {
        printf("EVENT_TCP_ACK_ATTACK_FIXED_BLOCK %s\n", src);
    }

    else if (reason == EVENT_TCP_RST_ATTACK_PROTECION_MODE_START) {
        printf("EVENT_TCP_RST_ATTACK_PROTECION_MODE_START\n");
    } else if (reason == EVENT_TCP_RST_ATTACK_PROTECION_MODE_END) {
        printf("EVENT_TCP_RST_ATTACK_PROTECION_MODE_END\n");
    } else if (reason == EVENT_TCP_RST_ATTACK_BURST_BLOCK) {
        printf("EVENT_TCP_RST_ATTACK_BURST_BLOCK %s\n", src);
    } else if (reason == EVENT_TCP_RST_ATTACK_FIXED_BLOCK) {
        printf("EVENT_TCP_RST_ATTACK_FIXED_BLOCK %s\n", src);
    }

    else if (reason == EVENT_ICMP_ATTACK_PROTECION_MODE_START) {
        printf("EVENT_ICMP_ATTACK_PROTECION_MODE_START\n");
    } else if (reason == EVENT_ICMP_ATTACK_PROTECION_MODE_END) {
        printf("EVENT_ICMP_ATTACK_PROTECION_MODE_END\n");
    } else if (reason == EVENT_ICMP_ATTACK_BURST_BLOCK) {
        printf("EVENT_ICMP_ATTACK_BURST_BLOCK %s\n", src);
    } else if (reason == EVENT_ICMP_ATTACK_FIXED_BLOCK) {
        printf("EVENT_ICMP_ATTACK_FIXED_BLOCK %s\n", src);
    }

    else if (reason == EVENT_UDP_ATTACK_PROTECION_MODE_START) {
        printf("EVENT_UDP_ATTACK_PROTECION_MODE_START\n");
    } else if (reason == EVENT_UDP_ATTACK_PROTECION_MODE_END) {
        printf("EVENT_UDP_ATTACK_PROTECION_MODE_END\n");
    } else if (reason == EVENT_UDP_ATTACK_BURST_BLOCK) {
        printf("EVENT_UDP_ATTACK_BURST_BLOCK %s\n", src);
    } else if (reason == EVENT_UDP_ATTACK_FIXED_BLOCK) {
        printf("EVENT_UDP_ATTACK_FIXED_BLOCK %s\n", src);
    }

    else if (reason == EVENT_GRE_ATTACK_PROTECION_MODE_START) {
        printf("EVENT_GRE_ATTACK_PROTECION_MODE_START\n");
    } else if (reason == EVENT_GRE_ATTACK_PROTECION_MODE_END) {
        printf("EVENT_GRE_ATTACK_PROTECION_MODE_END\n");
    } else if (reason == EVENT_GRE_ATTACK_BURST_BLOCK) {
        printf("EVENT_GRE_ATTACK_BURST_BLOCK %s\n", src);
    } else if (reason == EVENT_GRE_ATTACK_FIXED_BLOCK) {
        printf("EVENT_GRE_ATTACK_FIXED_BLOCK %s\n", src);
    }
}