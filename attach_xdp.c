// attach_xdp.c
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <linux/if_link.h>  // For XDP_FLAGS_* definitions
#include <libnetfilter_conntrack/libnetfilter_conntrack.h>
#include "common.h"

// Global configuration
char ifname[IFNAMSIZ];       // Network interface name
__u32 attach_mode;           // Attach mode of ebpf

static int event_cb(enum nf_conntrack_msg_type type,
                    struct nf_conntrack *ct,
                    void *data)
{
    struct tcp_session session = {0};
    __u8 value = 1;
    int err;
    int sessions_map_fd = *(int*)data;

    char buf[1024];
    nfct_snprintf(buf, sizeof(buf), ct, type, NFCT_O_DEFAULT, 0);
    printf("Conntrack event: %s\n", buf);

    /* Only handle TCP connections.
     * Use nfct_get_attr_u8() to retrieve the protocol.
     */
    uint8_t proto = nfct_get_attr_u8(ct, ATTR_ORIG_L4PROTO);
    if (proto != IPPROTO_TCP)
        return NFCT_CB_CONTINUE;

    /* Retrieve connection attributes.
     * Note: It's a good idea to check return values, but here we assume success.
     */
    session.src_ip = nfct_get_attr_u32(ct, ATTR_ORIG_IPV4_SRC);
    if (session.src_ip < 0)
        return NFCT_CB_CONTINUE;
    
    session.dst_ip = nfct_get_attr_u32(ct, ATTR_ORIG_IPV4_DST);
    if (session.dst_ip < 0)
        return NFCT_CB_CONTINUE;
    
    session.src_port = nfct_get_attr_u16(ct, ATTR_ORIG_PORT_SRC);
    if (session.src_port < 0)
        return NFCT_CB_CONTINUE;

    session.dst_port = nfct_get_attr_u16(ct, ATTR_ORIG_PORT_DST);
    if (session.dst_port < 0)
        return NFCT_CB_CONTINUE;

    /* For debugging, you might want to print the session information in hex,
     * but be careful with printing from kernel code.
     */

    printf("sessions_map_fd is %d, seesion is (%d:%d -> %d:%d)", sessions_map_fd, session.src_ip, session.src_port, session.dst_ip, session.dst_port);

    switch (type) {
    case NFCT_T_NEW:
    case NFCT_T_UPDATE:
        /* Update the BPF sessions map with the session key.
         * Here we use the global sessions_map_fd that was obtained during initialization.
         */
        err = bpf_map_update_elem(sessions_map_fd, &session, &value, BPF_ANY);
        if (err) {
            fprintf(stderr, "Failed to update session map: %d\n", err);
        }
        break;
    case NFCT_T_DESTROY:
        bpf_map_delete_elem(sessions_map_fd, &session);
        break;
    default:
        break;
    }

    return NFCT_CB_CONTINUE;
}
/* Global time offset (in nanoseconds) to convert from monotonic to real time */
static __u64 time_offset_ns = 0;

static long get_timezone_offset() {
    time_t t = time(NULL);
    struct tm local, utc;

    localtime_r(&t, &local);  // Local time (CST)
    gmtime_r(&t, &utc);       // UTC time

    // Calculate the difference in seconds
    long offset = (local.tm_hour - utc.tm_hour) * 3600
                + (local.tm_min - utc.tm_min) * 60
                + (local.tm_sec - utc.tm_sec);
    
    // Adjust for day difference (e.g., UTC+8 vs UTC-5)
    if (local.tm_mday != utc.tm_mday) {
        offset += (local.tm_mday > utc.tm_mday) ? 86400 : -86400;
    }
    
    return offset;
}

/* 
 * Initialize the time offset:
 *   time_offset = current_realtime - current_monotonic.
 */
static int init_time_offset(void)
{
    struct timespec ts_realtime, ts_monotonic;
    if (clock_gettime(CLOCK_REALTIME, &ts_realtime) != 0) {
        perror("clock_gettime(CLOCK_REALTIME)");
        return -1;
    }
    if (clock_gettime(CLOCK_MONOTONIC, &ts_monotonic) != 0) {
        perror("clock_gettime(CLOCK_MONOTONIC)");
        return -1;
    }
    __u64 realtime_ns = ts_realtime.tv_sec * ONE_SECOND_NS + ts_realtime.tv_nsec;
    __u64 monotonic_ns = ts_monotonic.tv_sec * ONE_SECOND_NS + ts_monotonic.tv_nsec;
    /* Compute offset; this is the amount that needs to be added to a monotonic time
       to get a (UTC) epoch time */
    if (realtime_ns > monotonic_ns)
        time_offset_ns = realtime_ns - monotonic_ns;
    else
        time_offset_ns = 0;  /* Fallback if something is wrong */

    return 0;
}


// Callback function invoked for each perf event.
static void handle_event(void *ctx, int cpu, void *data, __u32 size)
{
    struct event *e = data;
    char src[INET_ADDRSTRLEN];

    inet_ntop(AF_INET, &e->srcip, src, sizeof(src));

    /* Convert monotonic time to real time by adding the offset */
    __u64 real_time_ns = e->time + time_offset_ns;
    /* Apply timezone offset (CST = UTC+8) */
    long tz_offset_sec = get_timezone_offset();
    real_time_ns += tz_offset_sec * ONE_SECOND_NS;

    time_t seconds = real_time_ns / ONE_SECOND_NS;
    long nanos = real_time_ns % ONE_SECOND_NS;

    struct tm tm_info;
    if (localtime_r(&seconds, &tm_info) == NULL) {
        fprintf(stderr, "localtime_r error\n");
        return;
    }

    char buffer[26];
    strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", &tm_info);

    // Print the timestamp only once at the beginning
    printf("%s.%09ld    [cpu %d]    ", buffer, nanos, cpu);

    if (e->reason == EVENT_IP_BLOCK_END) {
        printf("EVENT_IP_BLOCK_END %s\n", src);
    } else if (e->reason == EVENT_TCP_SYN_ATTACK_PROTECION_MODE_START) {
        printf("EVENT_TCP_SYN_ATTACK_PROTECION_MODE_START\n");
    } else if (e->reason == EVENT_TCP_SYN_ATTACK_PROTECION_MODE_END) {
        printf("EVENT_TCP_SYN_ATTACK_PROTECION_MODE_END\n");
    } else if (e->reason == EVENT_TCP_SYN_ATTACK_BURST_BLOCK) {
        printf("EVENT_TCP_SYN_ATTACK_BURST_BLOCK %s\n", src);
    } else if (e->reason == EVENT_TCP_SYN_ATTACK_FIXED_BLOCK) {
        printf("EVENT_TCP_SYN_ATTACK_FIXED_BLOCK %s\n", src);
    }
}

/* Lost events callback (optional) */
void handle_lost(void *ctx, int cpu, __u32 lost)
{
    printf("Lost %u events on CPU %d\n", lost, cpu);
}

static volatile int exiting = 0;
static void sig_handler(int signo)
{
    exiting = 1;
}


// Trim whitespace from string
static void trim_whitespace(char *str) {
    char *end = str + strlen(str) - 1;
    while (end >= str && (*end == ' ' || *end == '\t' || *end == '\n')) end--;
    *(end + 1) = '\0';
}

static int load_config(struct bpf_object *obj) {
    if (init_time_offset() < 0) {
        fprintf(stderr, "Failed to initialize time offset\n");
        return 1;
    }

    FILE *fp = fopen(CONFIG_FILE, "r");
    if (!fp) {
        fprintf(stderr,"Failed to open config file");
        return -1;
    }

    // Set default values
    struct global_config gcfg = {0};
    strncpy(ifname, "eth0", IFNAMSIZ);
    attach_mode = XDP_FLAGS_SKB_MODE;
    gcfg.black_ip_duration = BLOCK_DURATION_NS;

    // Initialize SYN config with defaults
    struct syn_config syn_cfg = {
        .syn_threshold = SYN_THRESHOLD,
        .burst_pkt_threshold = SYN_BURST_PKT_THRESHOLD,
        .burst_count_threshold = SYN_BURST_COUNT_THRESHOLD,
        .challenge_timeout = SYN_CHALLENGE_TIMEOUT_NS,
        .syn_fixed_threshold = SYN_FIXED_THRESHOLD,
        .syn_fixed_check_duration = SYN_FIXED_CHECK_DURATION_NS,
    };

    struct ack_config ack_cfg = {
        .ack_threshold = ACK_THRESHOLD,
        .burst_pkt_threshold = ACK_BURST_PKT_THRESHOLD,
        .burst_count_threshold = ACK_BURST_COUNT_THRESHOLD,
        .ack_fixed_threshold = ACK_FIXED_THRESHOLD,
        .ack_fixed_check_duration = ACK_FIXED_CHECK_DURATION_NS,
    };

    struct rst_config rst_cfg = {
        .rst_threshold = RST_THRESHOLD,
        .burst_pkt_threshold = RST_BURST_PKT_THRESHOLD,
        .burst_count_threshold = RST_BURST_COUNT_THRESHOLD,
        .rst_fixed_threshold = RST_FIXED_THRESHOLD,
        .rst_fixed_check_duration = RST_FIXED_CHECK_DURATION_NS,
    };

    struct icmp_config icmp_cfg = {
        .icmp_threshold = ICMP_THRESHOLD,
        .burst_pkt_threshold = ICMP_BURST_PKT_THRESHOLD,
        .burst_count_threshold = ICMP_BURST_COUNT_THRESHOLD,
        .icmp_fixed_threshold = ICMP_FIXED_THRESHOLD,
        .icmp_fixed_check_duration = ICMP_FIXED_CHECK_DURATION_NS,
    };

    struct udp_config udp_cfg = {
        .udp_threshold = UDP_THRESHOLD,
        .burst_pkt_threshold = UDP_BURST_PKT_THRESHOLD,
        .burst_count_threshold = UDP_BURST_COUNT_THRESHOLD,
        .udp_fixed_threshold = UDP_FIXED_THRESHOLD,
        .udp_fixed_check_duration = UDP_FIXED_CHECK_DURATION_NS,
    };

    char line[MAX_LINE_LEN];
    while (fgets(line, sizeof(line), fp)) {
        // Skip comments and empty lines
        if (line[0] == '#' || line[0] == '\n') continue;

        char key[32] = {0};
        char str_value[IFNAMSIZ] = {0};
        int int_value;
        
        // Try to parse as key=string first (for device name)
        if (sscanf(line, "%31[^=]= %15s", key, str_value) == 2) {
            trim_whitespace(key);
            trim_whitespace(str_value);
            
            if (strcmp(key, "dev") == 0) {
                strncpy(ifname, str_value, IFNAMSIZ);
                printf("Loaded config: %s = %s\n", key, ifname);
                continue;
            }
            if (strcmp(key, "attach_mode") == 0) {
                /*XDP_FLAGS_UPDATE_IF_NOEXIST = (1 << 0)
                XDP_FLAGS_SKB_MODE = (1 << 1)
                XDP_FLAGS_DRV_MODE = (1 << 2)
                XDP_FLAGS_HW_MODE = (1 << 3)
                XDP_FLAGS_REPLACE = (1 << 4)*/
                printf("Loaded config: %s = %s\n", key, str_value);
                if (strcmp(str_value, "skb") == 0)
                    attach_mode = XDP_FLAGS_SKB_MODE;
                else if (strcmp(str_value, "native") == 0)
                    attach_mode = 0;
                else if (strcmp(str_value, "drive") == 0)
                    attach_mode = XDP_FLAGS_DRV_MODE;
                else if (strcmp(str_value, "hw") == 0)
                    attach_mode = XDP_FLAGS_HW_MODE;
                else {
                    fprintf(stderr,"Unkown attach_mode\n");
                    return -1;
                }
                continue;
            }
        }

        // Try to parse as key=integer
        if (sscanf(line, "%31[^=]= %d", key, &int_value) == 2) {
            trim_whitespace(key);
            
            printf("Loaded config: %s = %d\n", key, int_value);
            
            // Global config
            if (strcmp(key, "black_ip_duration") == 0) {
                gcfg.black_ip_duration = int_value * ONE_SECOND_NS;
            } 
            // SYN config
            else if (strcmp(key, "syn_threshold") == 0) {
                syn_cfg.syn_threshold = int_value;
            } else if (strcmp(key, "syn_burst_pkt") == 0) {
                syn_cfg.burst_pkt_threshold = int_value;
            } else if (strcmp(key, "syn_burst_count_per_sec") == 0) {
                syn_cfg.burst_count_threshold = int_value;
            } else if (strcmp(key, "challenge_timeout") == 0) {
                syn_cfg.challenge_timeout = int_value * ONE_SECOND_NS;
            } else if (strcmp(key, "syn_fixed_threshold") == 0) {
                syn_cfg.syn_fixed_threshold = int_value;
            } else if (strcmp(key, "syn_fixed_check_duration") == 0) {
                syn_cfg.syn_fixed_check_duration = int_value * ONE_SECOND_NS;
            } 
            //ACK config
            else if (strcmp(key, "ack_threshold") == 0) {
                ack_cfg.ack_threshold = int_value;
            } else if (strcmp(key, "ack_burst_pkt") == 0) {
                ack_cfg.burst_pkt_threshold = int_value;
            } else if (strcmp(key, "ack_burst_count_per_sec") == 0) {
                ack_cfg.burst_count_threshold = int_value;
            } else if (strcmp(key, "ack_fixed_threshold") == 0) {
                ack_cfg.ack_fixed_threshold = int_value;
            } else if (strcmp(key, "ack_fixed_check_duration") == 0) {
                ack_cfg.ack_fixed_check_duration = int_value * ONE_SECOND_NS;
            } 
            //RST config
            else if (strcmp(key, "rst_threshold") == 0) {
                rst_cfg.rst_threshold = int_value;
            } else if (strcmp(key, "rst_burst_pkt") == 0) {
                rst_cfg.burst_pkt_threshold = int_value;
            } else if (strcmp(key, "rst_burst_count_per_sec") == 0) {
                rst_cfg.burst_count_threshold = int_value;
            } else if (strcmp(key, "rst_fixed_threshold") == 0) {
                rst_cfg.rst_fixed_threshold = int_value;
            } else if (strcmp(key, "rst_fixed_check_duration") == 0) {
                rst_cfg.rst_fixed_check_duration = int_value * ONE_SECOND_NS;
            } 
            //ICMP config
            else if (strcmp(key, "icmp_threshold") == 0) {
                icmp_cfg.icmp_threshold = int_value;
            } else if (strcmp(key, "icmp_burst_pkt") == 0) {
                rst_cfg.burst_pkt_threshold = int_value;
            } else if (strcmp(key, "icmp_burst_count_per_sec") == 0) {
                rst_cfg.burst_count_threshold = int_value;
            } else if (strcmp(key, "icmp_fixed_threshold") == 0) {
                rst_cfg.rst_fixed_threshold = int_value;
            } else if (strcmp(key, "icmp_fixed_check_duration") == 0) {
                rst_cfg.rst_fixed_check_duration = int_value * ONE_SECOND_NS;
            } 
            //UDP config
            else if (strcmp(key, "udp_threshold") == 0) {
                udp_cfg.udp_threshold = int_value;
            } else if (strcmp(key, "udp_burst_pkt") == 0) {
                udp_cfg.burst_pkt_threshold = int_value;
            } else if (strcmp(key, "udp_burst_count_per_sec") == 0) {
                udp_cfg.burst_count_threshold = int_value;
            } else if (strcmp(key, "udp_fixed_threshold") == 0) {
                udp_cfg.udp_fixed_threshold = int_value;
            } else if (strcmp(key, "udp_fixed_check_duration") == 0) {
                udp_cfg.udp_fixed_check_duration = int_value * ONE_SECOND_NS;
            } 
            else {
                fprintf(stderr,"Unkown %s directive\n", key);
                return -1;
            }
        }
    }
    fclose(fp);

    // Calculate burst gap
    syn_cfg.burst_gap_ns = 1000000000ULL / (syn_cfg.burst_count_threshold);
    ack_cfg.burst_gap_ns = 1000000000ULL / (ack_cfg.burst_count_threshold);
    rst_cfg.burst_gap_ns = 1000000000ULL / (rst_cfg.burst_count_threshold);

    // Update SYN config map
    int syn_map_fd = bpf_object__find_map_fd_by_name(obj, "syn_config_map");
    if (syn_map_fd < 0) {
        fprintf(stderr, "Failed to find syn_config_map\n");
        return -1;
    }

    int key = 0;
    if (bpf_map_update_elem(syn_map_fd, &key, &syn_cfg, BPF_ANY)) {
        fprintf(stderr, "Failed to update syn_config_map\n");
        return -1;
    }

    // Update global config map
    int global_map_fd = bpf_object__find_map_fd_by_name(obj, "global_config_map");
    if (global_map_fd < 0) {
        fprintf(stderr, "Failed to find global_config_map\n");
        return -1;
    }
    
    if (bpf_map_update_elem(global_map_fd, &key, &gcfg, BPF_ANY)) {
        fprintf(stderr, "Failed to update global_config_map\n");
        return -1;
    }

    printf("Setup config success\n");

    return 0;
}


int main(int argc, char **argv) {
    
    int ifindex, err;
    struct bpf_object *obj;
    struct bpf_program *prog_main, *prog_parse_syn, *prog_parse_ack, *prog_parse_rst, *prog_parse_icmp, *prog_parse_udp;
    int attach_id = -1, prog_main_fd, prog_parse_syn_fd, prog_parse_ack_fd, prog_parse_rst_fd, prog_parse_icmp_fd, prog_parse_udp_fd;
    int prog_array_map_fd;
    struct perf_buffer *pb = NULL;
    
    // Open the BPF object file (compiled from xdp_prog.c).
    obj = bpf_object__open_file("xdp_prog.o", NULL);
    if (!obj) {
        fprintf(stderr, "ERROR: opening BPF object file failed\n");
        return 1;
    }
    
    // Load the BPF object into the kernel.
    err = bpf_object__load(obj);
    if (err) {
        fprintf(stderr, "ERROR: loading BPF object file: %d\n", err);
        goto cleanup;
    }

    if (load_config(obj) < 0) {
        goto cleanup;
    }

    // Get interface index.
    ifindex = if_nametoindex(ifname);
    if (!ifindex) {
        fprintf(stderr, "ERROR: if_nametoindex(%s) failed\n", ifname);
        return 1;
    }

    // Find program sections.
    prog_main = bpf_object__find_program_by_name(obj, "xdp_main");
    prog_parse_syn = bpf_object__find_program_by_name(obj, "xdp_parse_syn");
    prog_parse_ack = bpf_object__find_program_by_name(obj, "xdp_parse_ack");
    prog_parse_rst = bpf_object__find_program_by_name(obj, "xdp_parse_rst");
    prog_parse_icmp = bpf_object__find_program_by_name(obj, "xdp_parse_icmp");
    prog_parse_udp = bpf_object__find_program_by_name(obj, "xdp_parse_udp");

    if (!prog_main || !prog_parse_syn || !prog_parse_ack || !prog_parse_rst || !prog_parse_icmp || !prog_parse_udp) {
        fprintf(stderr, "ERROR: could not find all program sections\n");
        goto cleanup;
    }
    
    // Get file descriptors for the programs.
    prog_main_fd = bpf_program__fd(prog_main);
    prog_parse_syn_fd = bpf_program__fd(prog_parse_syn);
    prog_parse_ack_fd = bpf_program__fd(prog_parse_ack);
    prog_parse_rst_fd = bpf_program__fd(prog_parse_rst);
    prog_parse_icmp_fd = bpf_program__fd(prog_parse_icmp);
    prog_parse_udp_fd = bpf_program__fd(prog_parse_udp);
    
    // Find the prog_array map (declared as "prog_array" in our BPF program).
    struct bpf_map *map = bpf_object__find_map_by_name(obj, "prog_array");
    if (!map) {
        fprintf(stderr, "ERROR: could not find prog_array map\n");
        goto cleanup;
    }
    prog_array_map_fd = bpf_map__fd(map);
    
    // Update the prog_array map:
    // Key 0 -> xdp_parse_syn; Key 1 -> xdp_parse_ack.
    // Key 2 -> xdp_parse_rst; Key 3 -> xdp_parse_icmp. Key 4 -> xdp_parse_udp.
    int key0 = 0, key1 = 1, key2 = 2, key3 = 3, key4 = 4;
    err = bpf_map_update_elem(prog_array_map_fd, &key0, &prog_parse_syn_fd, 0);
    if (err) {
        fprintf(stderr, "ERROR: updating prog_array key 0 failed: %d\n", err);
        goto cleanup;
    }
    err = bpf_map_update_elem(prog_array_map_fd, &key1, &prog_parse_ack_fd, 0);
    if (err) {
        fprintf(stderr, "ERROR: updating prog_array key 1 failed: %d\n", err);
        goto cleanup;
    }
    err = bpf_map_update_elem(prog_array_map_fd, &key2, &prog_parse_rst_fd, 0);
    if (err) {
        fprintf(stderr, "ERROR: updating prog_array key 2 failed: %d\n", err);
        goto cleanup;
    }
    err = bpf_map_update_elem(prog_array_map_fd, &key3, &prog_parse_icmp_fd, 0);
    if (err) {
        fprintf(stderr, "ERROR: updating prog_array key 3 failed: %d\n", err);
        goto cleanup;
    }
    err = bpf_map_update_elem(prog_array_map_fd, &key4, &prog_parse_udp_fd, 0);
    if (err) {
        fprintf(stderr, "ERROR: updating prog_array key 4 failed: %d\n", err);
        goto cleanup;
    }
    
    // Attach the main XDP program to the interface.
    attach_id = bpf_xdp_attach(ifindex, prog_main_fd, attach_mode, NULL);
    if (attach_id < 0) {
        fprintf(stderr, "ERROR: attaching XDP program to %s (ifindex %d) failed: %d\n", ifname, ifindex, err);
        goto cleanup;
    }
    
    // Open the perf event array map.
    int map_fd = bpf_object__find_map_fd_by_name(obj, "events");
    if (map_fd < 0) {
        fprintf(stderr, "ERROR: finding map 'events'\n");
        goto cleanup;
    }
    pb = perf_buffer__new(map_fd, 8, handle_event, NULL, NULL, NULL);
    if (libbpf_get_error(pb)) {
        err = libbpf_get_error(pb);
        fprintf(stderr, "ERROR: opening perf buffer: %d\n", err);
        pb = NULL;
        goto cleanup;
    }

    printf("XDP program successfully attached to interface %s (ifindex %d)\n", ifname, ifindex);
    printf("Press Ctrl+C to exit and detach the program.\n");
    

    struct nfct_handle *cth;

    // Set up conntrack handler
    cth = nfct_open(CONNTRACK, NF_NETLINK_CONNTRACK_NEW | NF_NETLINK_CONNTRACK_UPDATE);
    if (!cth) {
        fprintf(stderr, "nfct_open");
        goto cleanup;
    }

    nfct_callback_register(cth, NFCT_T_ALL, event_cb, &map_fd);

    // Wait until terminated.
    while (!exiting) {
        err = perf_buffer__poll(pb, 100);
        if (err < 0 && err != -EINTR) {
            fprintf(stderr, "ERROR: perf_buffer__poll: %d\n", err);
            break;
        }
    }
    
cleanup:
    if (cth)
        nfct_close(cth);
    if (pb)
        perf_buffer__free(pb);
    // Detach the XDP program before exit.
    if (attach_id > 0)
        bpf_xdp_detach(ifindex, attach_mode, NULL);
    if (obj)
        bpf_object__close(obj);
    
    return err < 0 ? -err : 0;
}