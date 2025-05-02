#include <ebpf_firewall_common.h>
#include <ebpf_firewall_config.h>

// Global configuration
char ifname[IFNAMSIZ];       // Network interface name
__u32 attach_mode;           // Attach mode of ebpf
int n_cpus = 1;              // CPU count

/* Global time offset (in nanoseconds) to convert from monotonic to real time */
__u64 time_offset_ns = 0;
long tz_offset_sec = 0;      // Timezone offset

struct global_config gcfg = {0};

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

struct gre_config gre_cfg = {
    .gre_threshold = GRE_THRESHOLD,
    .burst_pkt_threshold = GRE_BURST_PKT_THRESHOLD,
    .burst_count_threshold = GRE_BURST_COUNT_THRESHOLD,
    .gre_fixed_threshold = GRE_FIXED_THRESHOLD,
    .gre_fixed_check_duration = GRE_FIXED_CHECK_DURATION_NS,
};


static int calc_cpus_count(void)
{
    return sysconf(_SC_NPROCESSORS_CONF);
}

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
int init_time_offset(void)
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

// Trim whitespace from string
static void trim_whitespace(char *str) {
    char *end = str + strlen(str) - 1;
    while (end >= str && (*end == ' ' || *end == '\t' || *end == '\n')) end--;
    *(end + 1) = '\0';
}

int load_config(struct bpf_object *obj) {

    FILE *fp = fopen(CONFIG_FILE, "r");
    if (!fp) {
        fprintf(stderr,"Failed to open config file");
        return -1;
    }

    // Set default values
    
    strncpy(ifname, "eth0", IFNAMSIZ);
    ifname[IFNAMSIZ-1] = '\0';
    n_cpus = calc_cpus_count();

    attach_mode = XDP_FLAGS_DRV_MODE;
    tz_offset_sec = get_timezone_offset();
    gcfg.black_ip_duration = BLOCK_DURATION_NS;

    char line[MAX_LINE_LEN];
    while (fgets(line, sizeof(line), fp)) {
        // Skip comments and empty lines
        if (line[0] == '#' || line[0] == '\n') continue;

        char key[128] = {0};
        char str_value[IFNAMSIZ] = {0};
        int int_value;
        
        // Try to parse as key=string first (for device name)
        if (sscanf(line, "%15[^=]= %31s", key, str_value) == 2) {
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
                else if (strcmp(str_value, "drv") == 0)
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
        if (sscanf(line, "%127[^=]= %d", key, &int_value) == 2) {
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
                icmp_cfg.burst_pkt_threshold = int_value;
            } else if (strcmp(key, "icmp_burst_count_per_sec") == 0) {
                icmp_cfg.burst_count_threshold = int_value;
            } else if (strcmp(key, "icmp_fixed_threshold") == 0) {
                icmp_cfg.icmp_fixed_threshold = int_value;
            } else if (strcmp(key, "icmp_fixed_check_duration") == 0) {
                icmp_cfg.icmp_fixed_check_duration = int_value * ONE_SECOND_NS;
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
            //GRE config
            else if (strcmp(key, "gre_threshold") == 0) {
                gre_cfg.gre_threshold = int_value;
            } else if (strcmp(key, "gre_burst_pkt") == 0) {
                gre_cfg.burst_pkt_threshold = int_value;
            } else if (strcmp(key, "gre_burst_count_per_sec") == 0) {
                gre_cfg.burst_count_threshold = int_value;
            } else if (strcmp(key, "gre_fixed_threshold") == 0) {
                gre_cfg.gre_fixed_threshold = int_value;
            } else if (strcmp(key, "gre_fixed_check_duration") == 0) {
                gre_cfg.gre_fixed_check_duration = int_value * ONE_SECOND_NS;
            }
            else {
                fprintf(stderr,"Unkown %s directive\n", key);
                return -1;
            }
        }
    }
    fclose(fp);
    
    if (syn_cfg.burst_count_threshold == 0) {
        fprintf(stderr,"Burst threshold of SYN is zero. Please reconfig it\n");
        return -1;
    }
    if (ack_cfg.burst_count_threshold == 0) {
        fprintf(stderr,"Burst threshold of ACK is zero. Please reconfig it\n");
        return -1;
    }
    if (rst_cfg.burst_count_threshold == 0) {
        fprintf(stderr,"Burst threshold of RST is zero. Please reconfig it\n");
        return -1;
    }
    if (icmp_cfg.burst_count_threshold == 0) {
        fprintf(stderr,"Burst threshold of ICMP is zero. Please reconfig it\n");
        return -1;
    }
    if (udp_cfg.burst_count_threshold == 0) {
        fprintf(stderr,"Burst threshold of UDP is zero. Please reconfig it\n");
        return -1;
    }
    if (gre_cfg.burst_count_threshold == 0) {
        fprintf(stderr,"Burst threshold of GRE is zero. Please reconfig it\n");
        return -1;
    }

    // Calculate burst gap
    syn_cfg.burst_gap_ns = ONE_SECOND_NS / (syn_cfg.burst_count_threshold);
    ack_cfg.burst_gap_ns = ONE_SECOND_NS / (ack_cfg.burst_count_threshold);
    rst_cfg.burst_gap_ns = ONE_SECOND_NS / (rst_cfg.burst_count_threshold);
    icmp_cfg.burst_gap_ns = ONE_SECOND_NS / (icmp_cfg.burst_count_threshold);
    udp_cfg.burst_gap_ns = ONE_SECOND_NS / (udp_cfg.burst_count_threshold);
    gre_cfg.burst_gap_ns = ONE_SECOND_NS / (gre_cfg.burst_count_threshold);

    // Update SYN config map
    int syn_map_fd = bpf_object__find_map_fd_by_name(obj, "syn_config_map");
    if (syn_map_fd < 0) {
        fprintf(stderr, "Failed to find syn_config_map\n");
        return -1;
    }

    int ack_map_fd = bpf_object__find_map_fd_by_name(obj, "ack_config_map");
    if (ack_map_fd < 0) {
        fprintf(stderr, "Failed to find ack_config_map\n");
        return -1;
    }

    int rst_map_fd = bpf_object__find_map_fd_by_name(obj, "rst_config_map");
    if (rst_map_fd < 0) {
        fprintf(stderr, "Failed to find rst_config_map\n");
        return -1;
    }

    int icmp_map_fd = bpf_object__find_map_fd_by_name(obj, "icmp_config_map");
    if (icmp_map_fd < 0) {
        fprintf(stderr, "Failed to find icmp_config_map\n");
        return -1;
    }

    int udp_map_fd = bpf_object__find_map_fd_by_name(obj, "udp_config_map");
    if (udp_map_fd < 0) {
        fprintf(stderr, "Failed to find udp_config_map\n");
        return -1;
    }

    int gre_map_fd = bpf_object__find_map_fd_by_name(obj, "gre_config_map");
    if (gre_map_fd < 0) {
        fprintf(stderr, "Failed to find gre_config_map\n");
        return -1;
    }

    int key = 0;
    if (bpf_map_update_elem(syn_map_fd, &key, &syn_cfg, BPF_ANY)) {
        fprintf(stderr, "Failed to update syn_config_map\n");
        return -1;
    }
    if (bpf_map_update_elem(ack_map_fd, &key, &ack_cfg, BPF_ANY)) {
        fprintf(stderr, "Failed to update ack_config_map\n");
        return -1;
    }
    if (bpf_map_update_elem(rst_map_fd, &key, &rst_cfg, BPF_ANY)) {
        fprintf(stderr, "Failed to update rst_config_map\n");
        return -1;
    }
    if (bpf_map_update_elem(icmp_map_fd, &key, &icmp_cfg, BPF_ANY)) {
        fprintf(stderr, "Failed to update icmp_config_map\n");
        return -1;
    }
    if (bpf_map_update_elem(udp_map_fd, &key, &udp_cfg, BPF_ANY)) {
        fprintf(stderr, "Failed to update udp_config_map\n");
        return -1;
    }
    if (bpf_map_update_elem(gre_map_fd, &key, &gre_cfg, BPF_ANY)) {
        fprintf(stderr, "Failed to update gre_config_map\n");
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

