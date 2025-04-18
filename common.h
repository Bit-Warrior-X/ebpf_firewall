#ifndef __COMMON_H
#define __COMMON_H

#include <linux/types.h>

// Define time constants (in nanoseconds)

#define MAX_LINE_LEN            128
#define CONFIG_FILE             "firewall.config"

#define ONE_SECOND_NS           1000000000ULL
#define BLOCK_DURATION_NS       (3600ULL * 1000000000ULL)  // 1 hour

#define SYN_THRESHOLD               200000                    // 200K SYN packets per second
#define SYN_BURST_PKT_THRESHOLD     20                        /* Each burst must have >=20 SYN packets */
#define SYN_BURST_COUNT_THRESHOLD   10                        /* 10 bursts per second triggers block */
#define SYN_FIXED_THRESHOLD         20000                     // Maximum SYN packets allowed in a 15-second window.
#define SYN_FIXED_CHECK_DURATION_NS (15ULL * ONE_SECOND_NS)   // 15 seconds for fixed duration check
#define SYN_CHALLENGE_TIMEOUT_NS    (2ULL * ONE_SECOND_NS)    // Timeout for challenge state
#define SYN_BURST_GAP_NS            ONE_SECOND_NS / SYN_BURST_COUNT_THRESHOLD    /* 100 ms gap ends a burst */

#define ACK_THRESHOLD               200000                    // 200K SYN packets per second
#define ACK_BURST_COUNT_THRESHOLD   100                       /* 10 bursts per second triggers block */
#define ACK_BURST_PKT_THRESHOLD     200                       /* Each burst must have >=20 SYN packets */
#define ACK_FIXED_THRESHOLD         20000                     // Maximum SYN packets allowed in a 15-second window.
#define ACK_FIXED_CHECK_DURATION_NS (15ULL * ONE_SECOND_NS)   // 15 seconds for fixed duration check
#define ACK_BURST_GAP_NS            ONE_SECOND_NS / ACK_BURST_PKT_THRESHOLD     

#define EVENT_IP_BLOCK_END                         0
#define EVENT_TCP_SYN_ATTACK_PROTECION_MODE_START  10
#define EVENT_TCP_SYN_ATTACK_PROTECION_MODE_END    11
#define EVENT_TCP_SYN_ATTACK_BURST_BLOCK           12
#define EVENT_TCP_SYN_ATTACK_FIXED_BLOCK           13

#define EVENT_TCP_ACK_ATTACK_PROTECION_MODE_START  20
#define EVENT_TCP_ACK_ATTACK_PROTECION_MODE_END    21
#define EVENT_TCP_ACK_ATTACK_BURST_BLOCK           22
#define EVENT_TCP_ACK_ATTACK_FIXED_BLOCK           23

struct global_config {
    __u64 black_ip_duration;     // Blacklist duration in seconds
};

struct event {
    __u64 time;
    __u16 reason;
    __u32 srcip;
};

// Existing counters for flood detection.
struct flood_stats {
    __u8  detected;
    __u64 count;
    __u64 last_ts;
};

// Per-source state for SYN packet bursts.
struct burst_state {
    __u64 last_pkt_time;       /* Timestamp of the last SYN packet */
    __u32 current_burst_count; /* Count of SYN packets in current burst */
    __u32 burst_count;         /* Number of bursts (which met the threshold) in current 1s window */
    __u64 last_reset;          /* Start time of the current 1-second window */
};

struct syn_config {
    __u32 syn_threshold;       
    __u64 burst_gap_ns; 
    __u32 burst_pkt_threshold;
    __u64 burst_count_threshold;
    __u64 challenge_timeout;
    __u32 syn_fixed_threshold;
    __u64 syn_fixed_check_duration;
};

struct ack_config {
    __u32 ack_threshold;       
    __u64 burst_gap_ns; 
    __u32 burst_pkt_threshold;
    __u64 burst_count_threshold;
    __u32 ack_fixed_threshold;
    __u64 ack_fixed_check_duration;
};

// New structure and map for the SYN challenge state.
struct challenge_state {
    __u8 stage;       // 1: first SYN seen; 2: challenge sent (waiting for client response)
    __u64 ts;         // Timestamp when state was updated
    __u32 seq;        // Seq Number of syn
    __u32 wrong_seq;  // An arbitrary “wrong” sequence number to send in our challenge SYN+ACK.
};


enum event_reason {
    EVENT_TCP_ACK_VALID = 1,
    EVENT_TCP_ACK_INVALID = 2,
};

struct tcp_session {
    __u32 src_ip;    // in network byte order
    __u16 src_port;  // in network byte order
    __u32 dst_ip;    // in network byte order
    __u16 dst_port;  // in network byte order
} __attribute__((packed));

#endif