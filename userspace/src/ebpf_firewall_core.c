#include <ebpf_firewall_common.h>
#include <ebpf_firewall_log.h>
#include <ebpf_firewall_unix.h>
#include <ebpf_firewall_config.h>


extern char ifname[IFNAMSIZ];       // Network interface name
extern __u32 attach_mode;           // Attach mode of ebpf
extern int n_cpus;                  // CPU count
extern __u64 time_offset_ns;        // Timeo offset ns
extern long tz_offset_sec;          // Timezone offset

int exiting = 0;
char **process_argv = NULL;
struct bpf_object *obj;

static void sig_handler(int signo)
{
    exiting = 1;
}

extern struct global_config gcfg;
extern struct syn_config syn_cfg;
extern struct ack_config ack_cfg;
extern struct rst_config rst_cfg;
extern struct icmp_config icmp_cfg;
extern struct udp_config udp_cfg;
extern struct gre_config gre_cfg;

static void * global_attack_check_worker(void * arg) {

    size_t vsize = sizeof(__u64) * n_cpus;
    __u64 *values = calloc(n_cpus, sizeof(__u64));
    
    struct bpf_object *obj = (struct bpf_object*)arg;

    int global_attack_stats_map_fd;
    int global_syn_pkt_counter_map_fd, global_ack_pkt_counter_map_fd, global_rst_pkt_counter_map_fd, global_icmp_pkt_counter_map_fd, global_udp_pkt_counter_map_fd, global_gre_pkt_counter_map_fd;

    global_attack_stats_map_fd = bpf_object__find_map_fd_by_name(obj, "global_attack_stats_map");
    if (global_attack_stats_map_fd < 0) {
        fprintf(stderr, "Failed to find global_attack_stats_map eBPF map\n");
        goto cleanup;
    }

    global_syn_pkt_counter_map_fd = bpf_object__find_map_fd_by_name(obj, "global_syn_pkt_counter");
    if (global_syn_pkt_counter_map_fd < 0) {
        fprintf(stderr, "Failed to find global_syn_pkt_counter eBPF map\n");
        goto cleanup;
    }

    global_ack_pkt_counter_map_fd = bpf_object__find_map_fd_by_name(obj, "global_ack_pkt_counter");
    if (global_ack_pkt_counter_map_fd < 0) {
        fprintf(stderr, "Failed to find global_ack_pkt_counter eBPF map\n");
        goto cleanup;
    }

    global_rst_pkt_counter_map_fd = bpf_object__find_map_fd_by_name(obj, "global_rst_pkt_counter");
    if (global_rst_pkt_counter_map_fd < 0) {
        fprintf(stderr, "Failed to find global_rst_pkt_counter eBPF map\n");
        goto cleanup;
    }

    global_icmp_pkt_counter_map_fd = bpf_object__find_map_fd_by_name(obj, "global_icmp_pkt_counter");
    if (global_icmp_pkt_counter_map_fd < 0) {
        fprintf(stderr, "Failed to find global_icmp_pkt_counter eBPF map\n");
        goto cleanup;
    }

    global_udp_pkt_counter_map_fd = bpf_object__find_map_fd_by_name(obj, "global_udp_pkt_counter");
    if (global_udp_pkt_counter_map_fd < 0) {
        fprintf(stderr, "Failed to find global_udp_pkt_counter eBPF map\n");
        goto cleanup;
    }

    global_gre_pkt_counter_map_fd = bpf_object__find_map_fd_by_name(obj, "global_gre_pkt_counter");
    if (global_gre_pkt_counter_map_fd < 0) {
        fprintf(stderr, "Failed to find global_gre_pkt_counter eBPF map\n");
        goto cleanup;
    }

    while (!exiting) {
        __u32 key = 0;
        time_t now = time(NULL);     /* current epoch seconds */
        //printf("[Global statistic] check @ %s", ctime(&now));   /* ctime() adds \n */

        struct global_attack_stats global_attack_stats_val;
        if (bpf_map_lookup_elem(global_attack_stats_map_fd, &key, &global_attack_stats_val)) {
            fprintf(stderr, "bpf_map_lookup_elem");
            goto cleanup;
        }
        
        __u64 total_syn_cnt = 0;
        if (bpf_map_lookup_elem(global_syn_pkt_counter_map_fd, &key, values)) {
            fprintf(stderr, "bpf_map_lookup_elem");
            goto cleanup;
        }
        for (int cpu = 0; cpu < n_cpus; cpu++) {
            total_syn_cnt += values[cpu];
        }
        memset(values, 0, vsize);
        if (bpf_map_update_elem(global_syn_pkt_counter_map_fd, &key, values, 0)) {
            fprintf(stderr, "bpf_map_update_elem");
            goto cleanup;
        }

        __u64 total_ack_cnt = 0;
        if (bpf_map_lookup_elem(global_ack_pkt_counter_map_fd, &key, values)) {
            fprintf(stderr, "bpf_map_lookup_elem");
            goto cleanup;
        }
        for (int cpu = 0; cpu < n_cpus; cpu++) {
            total_ack_cnt += values[cpu];
        }
        memset(values, 0, vsize);
        if (bpf_map_update_elem(global_ack_pkt_counter_map_fd, &key, values, 0)) {
            fprintf(stderr, "bpf_map_update_elem");
            goto cleanup;
        }

        __u64 total_rst_cnt = 0;
        if (bpf_map_lookup_elem(global_rst_pkt_counter_map_fd, &key, values)) {
            fprintf(stderr, "bpf_map_lookup_elem");
            goto cleanup;
        }
        for (int cpu = 0; cpu < n_cpus; cpu++) {
            total_rst_cnt += values[cpu];
        }
        memset(values, 0, vsize);
        if (bpf_map_update_elem(global_rst_pkt_counter_map_fd, &key, values, 0)) {
            fprintf(stderr, "bpf_map_update_elem");
            goto cleanup;
        }

        __u64 total_icmp_cnt = 0;
        if (bpf_map_lookup_elem(global_icmp_pkt_counter_map_fd, &key, values)) {
            fprintf(stderr, "bpf_map_lookup_elem");
            goto cleanup;
        }
        for (int cpu = 0; cpu < n_cpus; cpu++) {
            total_icmp_cnt += values[cpu];
        }
        memset(values, 0, vsize);
        if (bpf_map_update_elem(global_icmp_pkt_counter_map_fd, &key, values, 0)) {
            fprintf(stderr, "bpf_map_update_elem");
            goto cleanup;
        }

        __u64 total_udp_cnt = 0;
        if (bpf_map_lookup_elem(global_udp_pkt_counter_map_fd, &key, values)) {
            fprintf(stderr, "bpf_map_lookup_elem");
            goto cleanup;
        }
        for (int cpu = 0; cpu < n_cpus; cpu++) {
            total_udp_cnt += values[cpu];
        }
        memset(values, 0, vsize);
        if (bpf_map_update_elem(global_udp_pkt_counter_map_fd, &key, values, 0)) {
            fprintf(stderr, "bpf_map_update_elem");
            goto cleanup;
        }

        __u64 total_gre_cnt = 0;
        if (bpf_map_lookup_elem(global_gre_pkt_counter_map_fd, &key, values)) {
            fprintf(stderr, "bpf_map_lookup_elem");
            goto cleanup;
        }
        for (int cpu = 0; cpu < n_cpus; cpu++) {
            total_gre_cnt += values[cpu];
        }
        memset(values, 0, vsize);
        if (bpf_map_update_elem(global_gre_pkt_counter_map_fd, &key, values, 0)) {
            fprintf(stderr, "bpf_map_update_elem");
            goto cleanup;
        }

        time_t rawtime;
        struct tm *tm_info;
        time(&rawtime);
        tm_info = localtime(&rawtime);

        __u8 need_to_update = false;
        __u8 syn_attack = false, ack_attack = false, rst_attack = false, icmp_attack = false, udp_attack = false, gre_attack = false;

        if (total_syn_cnt >= syn_cfg.syn_threshold) syn_attack = true;
        else syn_attack = false;
        if (syn_attack != global_attack_stats_val.syn_attack) {
            if (syn_attack == true) {
                print_firewall_status(tm_info, EVENT_TCP_SYN_ATTACK_PROTECION_MODE_START, 0);
            } else {
                print_firewall_status(tm_info, EVENT_TCP_SYN_ATTACK_PROTECION_MODE_END, 0);
            }
            global_attack_stats_val.syn_attack = syn_attack;
            need_to_update = true;
        }

        if (total_ack_cnt >= ack_cfg.ack_threshold) ack_attack = true;
        else ack_attack = false;
        if (ack_attack != global_attack_stats_val.ack_attack) {
            if (ack_attack == true) {
                print_firewall_status(tm_info, EVENT_TCP_ACK_ATTACK_PROTECION_MODE_START, 0);
            } else {
                print_firewall_status(tm_info, EVENT_TCP_ACK_ATTACK_PROTECION_MODE_END, 0);
            }
            global_attack_stats_val.ack_attack = ack_attack;
            need_to_update = true;
        }

        if (total_rst_cnt >= rst_cfg.rst_threshold) rst_attack = true;
        else rst_attack = false;
        if (rst_attack != global_attack_stats_val.rst_attack) {
            if (rst_attack == true) {
                print_firewall_status(tm_info, EVENT_TCP_RST_ATTACK_PROTECION_MODE_START, 0);
            } else {
                print_firewall_status(tm_info, EVENT_TCP_RST_ATTACK_PROTECION_MODE_END, 0);
            }
            global_attack_stats_val.rst_attack = rst_attack;
            need_to_update = true;
        }

        if (total_icmp_cnt >= icmp_cfg.icmp_threshold) icmp_attack = true;
        else icmp_attack = false;
        if (icmp_attack != global_attack_stats_val.icmp_attack) {
            if (icmp_attack == true) {
                print_firewall_status(tm_info, EVENT_ICMP_ATTACK_PROTECION_MODE_START, 0);
            } else {
                print_firewall_status(tm_info, EVENT_ICMP_ATTACK_PROTECION_MODE_END, 0);
            }
            global_attack_stats_val.icmp_attack = icmp_attack;
            need_to_update = true;
        }

        if (total_udp_cnt >= udp_cfg.udp_threshold) udp_attack = true;
        else udp_attack = false;
        if (udp_attack != global_attack_stats_val.udp_attack) {
            if (udp_attack == true) {
                print_firewall_status(tm_info, EVENT_UDP_ATTACK_PROTECION_MODE_START, 0);
            } else {
                print_firewall_status(tm_info, EVENT_UDP_ATTACK_PROTECION_MODE_END, 0);
            }
            global_attack_stats_val.udp_attack = udp_attack;
            need_to_update = true;
        }

        if (total_gre_cnt >= gre_cfg.gre_threshold) gre_attack = true;
        else gre_attack = false;
        if (gre_attack != global_attack_stats_val.gre_attack) {
            if (gre_attack == true) {
                print_firewall_status(tm_info, EVENT_GRE_ATTACK_PROTECION_MODE_START, 0);
            } else {
                print_firewall_status(tm_info, EVENT_GRE_ATTACK_PROTECION_MODE_END, 0);
            }
            global_attack_stats_val.gre_attack = gre_attack;
            need_to_update = true;
        }


        if (need_to_update == true)
            bpf_map_update_elem(global_attack_stats_map_fd, &key, &global_attack_stats_val, 0);

        sleep (1);
    }

cleanup:
    if (values) free (values);
    return NULL;
}

static int network_event_cb(enum nf_conntrack_msg_type type,
                    struct nf_conntrack *ct,
                    void *data)
{
    __u32 srcip = 0;
    __u16 src_port = 0;
    __u8 value = 1;
    int err;
    
    if (data == NULL)
        return NFCT_CB_CONTINUE;

    int tcp_established_map_fd = *(int*)data;

    uint8_t proto = nfct_get_attr_u8(ct, ATTR_ORIG_L4PROTO);
    if (proto != IPPROTO_TCP)
        return NFCT_CB_CONTINUE;

    srcip = nfct_get_attr_u32(ct, ATTR_ORIG_IPV4_SRC);
    if (srcip <= 0)
       return NFCT_CB_CONTINUE;

    src_port = nfct_get_attr_u16(ct, ATTR_ORIG_PORT_SRC);
    if (src_port < 0)
        return NFCT_CB_CONTINUE;

    __u64 key = src_port;
    key = ((key << 32) | srcip);

    uint8_t tcp_state = nfct_get_attr_u8(ct, ATTR_TCP_STATE);
    
    switch (type) {
    case NFCT_T_NEW:
        break;
    case NFCT_T_UPDATE:
        if (tcp_state == 3) { //Established
            printf("Established source is %x:%d\n", htonl(srcip), htons(src_port));
            err = bpf_map_update_elem(tcp_established_map_fd, &key, &value, BPF_ANY);
            if (err) {
                fprintf(stderr, "Failed to update tcp_established_session map: %d\n", err);
            }
        }
        break;
    case NFCT_T_DESTROY:
        printf("Destroy source is %x:%d\n", htonl(srcip), htons(src_port));
        bpf_map_delete_elem(tcp_established_map_fd, &key);
        break;
    default:
        break;
    }

    return NFCT_CB_CONTINUE;
}

// Callback function invoked for each perf event.
static int ringbuf_handle_event(void *ctx, void *data, size_t size)
{
    struct event *e = data;
    /* Convert monotonic time to real time by adding the offset */
    __u64 real_time_ns = e->time + time_offset_ns;
    /* Apply timezone offset (CST = UTC+8) */
    real_time_ns += tz_offset_sec * ONE_SECOND_NS;
    time_t seconds = real_time_ns / ONE_SECOND_NS;

    struct tm tm_info;
    if (localtime_r(&seconds, &tm_info) == NULL) {
        fprintf(stderr, "localtime_r error\n");
        return -1;
    }

    print_firewall_status(&tm_info, e->reason, e->srcip);
    return 0;
}


int main(int argc, char **argv) {
    
    int ifindex, err;
    struct bpf_program *prog_main, *prog_parse_syn, *prog_parse_ack, *prog_parse_rst, *prog_parse_icmp, *prog_parse_udp, *prog_parse_gre;
    int attach_id = -1, prog_main_fd, prog_parse_syn_fd, prog_parse_ack_fd, prog_parse_rst_fd, prog_parse_icmp_fd, prog_parse_udp_fd, prog_parse_gre_fd;
    int prog_array_map_fd;
    int tcp_established_map_fd;
    struct perf_buffer *pb = NULL;
    struct ring_buffer *ringbuf = NULL;
    
    // Open the BPF object file (compiled from xdp_prog.c).
    obj = bpf_object__open_file(XDP_CORE_FILE, NULL);
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

    if (init_unix_socket() < 0) {
        fprintf(stderr, "Failed to init unix socket\n");
        goto cleanup;
    }

    if (init_time_offset() < 0) {
        fprintf(stderr, "Failed to initialize time offset\n");
        goto cleanup;
    }

    if (load_config(obj) < 0) {
        goto cleanup;
    }

    process_argv = argv;

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
    prog_parse_gre = bpf_object__find_program_by_name(obj, "xdp_parse_gre");

    if (!prog_main || !prog_parse_syn || !prog_parse_ack || !prog_parse_rst || !prog_parse_icmp || !prog_parse_udp || !prog_parse_gre) {
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
    prog_parse_gre_fd = bpf_program__fd(prog_parse_gre);
    
    // Find the prog_array map (declared as "prog_array" in our BPF program).
    struct bpf_map *map = bpf_object__find_map_by_name(obj, "prog_array");
    if (!map) {
        fprintf(stderr, "ERROR: could not find prog_array map\n");
        goto cleanup;
    }
    prog_array_map_fd = bpf_map__fd(map);
    
    // Update the prog_array map:
    // Key 0 -> xdp_parse_syn; Key 1 -> xdp_parse_ack.
    // Key 2 -> xdp_parse_rst; Key 3 -> xdp_parse_icmp. Key 4 -> xdp_parse_udp. Key 5 -> xdp_parse_gre.
    int key0 = 0, key1 = 1, key2 = 2, key3 = 3, key4 = 4, key5 = 5;
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
    err = bpf_map_update_elem(prog_array_map_fd, &key5, &prog_parse_gre_fd, 0);
    if (err) {
        fprintf(stderr, "ERROR: updating prog_array key 5 failed: %d\n", err);
        goto cleanup;
    }
    
    // Attach the main XDP program to the interface.
    attach_id = bpf_xdp_attach(ifindex, prog_main_fd, attach_mode, NULL);
    if (attach_id < 0) {
        fprintf(stderr, "ERROR: attaching XDP program to %s (ifindex %d) return %d, failed: %d\n", ifname, ifindex, attach_id, err);
        goto cleanup;
    }

    //Open Ringbuf map
    int ring_buf_events_map_fd = bpf_object__find_map_fd_by_name(obj, "ring_buf_events");
    if (ring_buf_events_map_fd < 0) {
        fprintf(stderr, "ERROR: finding map 'ring_buf_events'\n");
        goto cleanup;
    }
    
    // Set up ring buffer
    ringbuf = ring_buffer__new(ring_buf_events_map_fd, ringbuf_handle_event, NULL, NULL);
    if (!ringbuf) {
        fprintf(stderr, "Failed to create ring buffer\n");
        err = -1;
        goto cleanup;
    }

    signal(SIGINT, sig_handler);

    // Get the map file descriptor
    tcp_established_map_fd = bpf_object__find_map_fd_by_name(obj, "tcp_established_map");
    if (tcp_established_map_fd < 0) {
        fprintf(stderr, "Failed to find tcp_established_map eBPF map\n");
        goto cleanup;
    }

    struct nfct_handle *cth;
    static const int family = AF_INET;

    // Set up conntrack handler
    cth = nfct_open(CONNTRACK, 0);
    if (!cth) {
        perror("nfct_open");
        goto cleanup;
    }

    nfct_callback_register(cth, NFCT_T_ALL, network_event_cb, &tcp_established_map_fd);
    printf("Established connections:\n");
    nfct_query(cth, NFCT_Q_DUMP, &family);
    nfct_close(cth);

    cth = nfct_open(CONNTRACK, NFCT_ALL_CT_GROUPS);
    if (!cth) {
        perror("nfct_open");
        goto cleanup;
    }

    nfct_callback_register(cth, NFCT_T_ALL, network_event_cb, &tcp_established_map_fd);

    pthread_t ct_thr; 
    if (pthread_create(&ct_thr, NULL, (void *(*)(void *))nfct_catch, cth) != 0) {
        perror("pthread_create for ct_thr");
        goto cleanup;
    }

    pthread_t global_attack_ch_thr;
    if (pthread_create(&global_attack_ch_thr, NULL, global_attack_check_worker, obj) != 0) {
        perror("pthread_create for global_attack_ch_thr");
        goto cleanup;
    }

    printf("XDP program successfully attached to interface %s (ifindex %d)\n", ifname, ifindex);
    printf("Press Ctrl+C to exit and detach the program.\n");

    // Wait until terminated.
    while (!exiting) {
        err = ring_buffer__poll(ringbuf, 100 /* timeout, ms */);
        if (err == -EINTR) {
            err = 0;
            break;
        }
        if (err < 0) {
            fprintf(stderr, "Error polling ring buffer: %d\n", err);
            break;
        }
    }
    
cleanup:
    if (cth) nfct_close(cth);
    if (ringbuf) ring_buffer__free(ringbuf);
    if (obj) bpf_object__close(obj);
    if (attach_id >= 0) bpf_xdp_detach(ifindex, attach_mode, NULL);
    
    close_unix_socket();

    printf("Program is ended\n");

    return err < 0 ? -err : 0;
}


int restart_fw() {
    int ret = -1;

    if (process_argv == NULL) {
        fprintf(stderr, "Process argument is NULL\n");
        return -1;
    }

    ret = execvp(process_argv[0], process_argv);
    if (ret == -1) {
        fprintf(stderr, "Process did not terminate correctly\n");
        return -1;
    }

    return ret;
}

#if 0
/* -------------------------------------------------------------- */
/* Core: count elements in map_fd, independent of key/value sizes */
static long count_map(int map_fd)
{
    struct bpf_map_info info = {};
    __u32 len = sizeof(info);
    if (bpf_obj_get_info_by_fd(map_fd, &info, &len)) {
        perror("bpf_obj_get_info_by_fd");
        return -1;
    }

#if defined(BPF_MAP_LOOKUP_BATCH)   /* kernel ≥ 5.6 ---------------------- */
    const __u32 BATCH = 256;
    void *keys = malloc(BATCH * info.key_size);
    void *vals = info.value_size ? malloc(BATCH * info.value_size) : NULL;
    void *in_key = NULL, *out_key = malloc(info.key_size);
    if (!keys || (!vals && info.value_size) || !out_key) {
        fprintf(stderr, "OOM\n");
        goto err_batch;
    }

    long total = 0;
    for (;;) {
        __u32 cnt = BATCH;
        int err = bpf_map_lookup_batch(map_fd,
                                       in_key, out_key,
                                       keys, vals, &cnt, NULL);
        if (err) {
            if (errno == ENOENT)    /* map exhausted */
                break;
            perror("bpf_map_lookup_batch");
            goto err_batch;
        }
        total += cnt;
        if (cnt < BATCH)            /* short read → nothing left */
            break;
        in_key = out_key;           /* continue where we stopped */
    }

    free(keys); free(vals); free(out_key);
    return total;

err_batch:
    free(keys); free(vals); free(out_key);
    return -1;

#else                               /* fallback: GET_NEXT_KEY loop ------- */
    void *key = calloc(1, info.key_size);
    void *next = calloc(1, info.key_size);
    if (!key || !next) {
        fprintf(stderr, "OOM\n");
        free(key); free(next);
        return -1;
    }

    long total = 0;
    /* first call: NULL → first key */
    if (bpf_map_get_next_key(map_fd, NULL, next))
        goto done;                  /* map empty */

    do {
        ++total;
        memcpy(key, next, info.key_size);
    } while (!bpf_map_get_next_key(map_fd, key, next));

done:
    free(key); free(next);
    return total;
#endif
}
#endif

static int clear_batch_map(int map_fd)
{   
    const __u32 BATCH_SZ = 256;
    struct bpf_map_info info = {};
    __u32 info_len = sizeof(info);
    int err;

    if (bpf_obj_get_info_by_fd(map_fd, &info, &info_len)) {
        perror("bpf_obj_get_info_by_fd");
        return -1;
    }

    /* --- allocate buffers ------------------------------------------------ */
    void *keys   = calloc(BATCH_SZ, info.key_size);
    void *values = info.value_size ? calloc(BATCH_SZ, info.value_size) : NULL;
    void *next_key = malloc(info.key_size);          /* out_batch scratch */

    if (!keys || (info.value_size && !values) || !next_key) {
        fprintf(stderr, "clear_map: out of memory\n");
        goto error;
    }

    /* --- iterate & delete ------------------------------------------------ */
    void *in_key = NULL;            /* start from beginning */
    __u32 total = 0;

    for (;;) {
        __u32 cnt = BATCH_SZ;

        err = bpf_map_lookup_and_delete_batch(map_fd,
                                              in_key,          /* in_batch  */
                                              next_key,        /* out_batch */
                                              keys,
                                              values,
                                              &cnt,
                                              NULL);
        if (err) {
            if (errno == ENOENT)         /* map already empty */
                break;
            perror("bpf_map_lookup_and_delete_batch");
            goto error;
        }

        if (cnt < BATCH_SZ)              /* short batch → nothing left */
            break;

        in_key = next_key;               /* continue from where we stopped */
    }

    free(keys); free(values); free(next_key);
    return 0;

error:
    free(keys); free(values); free(next_key);
    return -1;
}

static int clear_pkt_counter_map(int map_fd) {
    __u32 key = 0;
    __u64 *values = calloc(n_cpus, sizeof(__u64));

    if (values == NULL)
        goto error;

    if (bpf_map_lookup_elem(map_fd, &key, values)) {
        fprintf(stderr, "bpf_map_lookup_elem");
        goto error;
    }
    for (int cpu = 0; cpu < n_cpus; cpu++) {
        values[cpu] = 0;
    }

    bpf_map_update_elem(map_fd, &key, values, 0);
    if (values) free (values);
    return 0;
error:
    if (values) free (values);
    return -1;
}

static int clear_global_attack_stats_map(int map_fd) {
    __u32 key = 0;
    struct global_attack_stats global_attack_stats_val;

    if (bpf_map_lookup_elem(map_fd, &key, &global_attack_stats_val)) {
        fprintf(stderr, "bpf_map_lookup_elem");
        return -1;
    }
    memset(&global_attack_stats_val, 0 , sizeof (struct global_attack_stats));
    bpf_map_update_elem(map_fd, &key, &global_attack_stats_val, 0);
    return 0;
}

int clear_fw() {
#if 0
    int blocked_ips_fd;
    blocked_ips_fd = bpf_object__find_map_fd_by_name(obj, "blocked_ips");
    if (blocked_ips_fd < 0) {
        fprintf(stderr, "Failed to find blocked_ips\n");
        return -1;
    }
    printf("total registered count is %d\n", count_map(blocked_ips_fd));
    if (clear_batch_map(blocked_ips_fd) < 0)
        return -1;
    printf("blocked_ips_fd is cleared\n");
    printf("After clear total registered count is %d\n", count_map(blocked_ips_fd));
#endif
    int tcp_established_map_fd, global_attack_stats_map_fd;

    tcp_established_map_fd = bpf_object__find_map_fd_by_name(obj, "tcp_established_map");
    if (tcp_established_map_fd < 0) {
        fprintf(stderr, "Failed to find tcp_established_map\n");
        return -1;
    }
    if (clear_batch_map(tcp_established_map_fd) < 0)
        return -1;
    printf("tcp_established_map is cleared\n");
    
    global_attack_stats_map_fd = bpf_object__find_map_fd_by_name(obj, "global_attack_stats_map");
    if (global_attack_stats_map_fd < 0) {
        fprintf(stderr, "Failed to find global_attack_stats_map\n");
        return -1;
    }
    if (clear_global_attack_stats_map(global_attack_stats_map_fd) < 0)
        return -1;
    printf("global_attack_stats_map is cleared\n");

    int global_syn_pkt_counter_fd, syn_counter_fixed_fd, burst_syn_state_fd, syn_challenge_fd;
    global_syn_pkt_counter_fd = bpf_object__find_map_fd_by_name(obj, "global_syn_pkt_counter");
    if (global_syn_pkt_counter_fd < 0) {
        fprintf(stderr, "Failed to find global_syn_pkt_counter\n");
        return -1;
    }
    if (clear_pkt_counter_map(global_syn_pkt_counter_fd) < 0)
        return -1;
    printf("global_syn_pkt_counter is cleared\n");  

    syn_counter_fixed_fd = bpf_object__find_map_fd_by_name(obj, "syn_counter_fixed");
    if (syn_counter_fixed_fd < 0) {
        fprintf(stderr, "Failed to find syn_counter_fixed\n");
        return -1;
    }
    if (clear_batch_map(syn_counter_fixed_fd) < 0)
        return -1;
    printf("syn_counter_fixed is cleared\n");  

    burst_syn_state_fd = bpf_object__find_map_fd_by_name(obj, "burst_syn_state");
    if (burst_syn_state_fd < 0) {
        fprintf(stderr, "Failed to find burst_syn_state\n");
        return -1;
    }
    if (clear_batch_map(burst_syn_state_fd) < 0)
        return -1;
    printf("burst_syn_state is cleared\n");  

    syn_challenge_fd = bpf_object__find_map_fd_by_name(obj, "syn_challenge");
    if (syn_challenge_fd < 0) {
        fprintf(stderr, "Failed to find syn_challenge\n");
        return -1;
    }
    if (clear_batch_map(syn_challenge_fd) < 0)
        return -1;
    printf("syn_challenge is cleared\n");  

    int global_ack_pkt_counter_fd, ack_counter_fixed_fd, burst_ack_state_fd;
    global_ack_pkt_counter_fd = bpf_object__find_map_fd_by_name(obj, "global_ack_pkt_counter");
    if (global_ack_pkt_counter_fd < 0) {
        fprintf(stderr, "Failed to find global_ack_pkt_counter\n");
        return -1;
    }
    if (clear_pkt_counter_map(global_ack_pkt_counter_fd) < 0)
        return -1;
    printf("global_ack_pkt_counter is cleared\n");  

    ack_counter_fixed_fd = bpf_object__find_map_fd_by_name(obj, "ack_counter_fixed");
    if (ack_counter_fixed_fd < 0) {
        fprintf(stderr, "Failed to find ack_counter_fixed\n");
        return -1;
    }
    if (clear_batch_map(ack_counter_fixed_fd) < 0)
        return -1;
    printf("ack_counter_fixed is cleared\n"); 

    burst_ack_state_fd = bpf_object__find_map_fd_by_name(obj, "burst_ack_state");
    if (burst_ack_state_fd < 0) {
        fprintf(stderr, "Failed to find burst_ack_state\n");
        return -1;
    }
    if (clear_batch_map(burst_ack_state_fd) < 0)
        return -1;
    printf("burst_ack_state is cleared\n"); 

    int global_rst_pkt_counter_fd, rst_counter_fixed_fd, burst_rst_state_fd;
    global_rst_pkt_counter_fd = bpf_object__find_map_fd_by_name(obj, "global_rst_pkt_counter");
    if (global_rst_pkt_counter_fd < 0) {
        fprintf(stderr, "Failed to find global_rst_pkt_counter\n");
        return -1;
    }
    if (clear_pkt_counter_map(global_rst_pkt_counter_fd) < 0)
        return -1;
    printf("global_rst_pkt_counter is cleared\n"); 

    rst_counter_fixed_fd = bpf_object__find_map_fd_by_name(obj, "rst_counter_fixed");
    if (rst_counter_fixed_fd < 0) {
        fprintf(stderr, "Failed to find rst_counter_fixed\n");
        return -1;
    }
    if (clear_batch_map(rst_counter_fixed_fd) < 0)
        return -1;
    printf("rst_counter_fixed is cleared\n");

    burst_rst_state_fd = bpf_object__find_map_fd_by_name(obj, "burst_rst_state");
    if (burst_rst_state_fd < 0) {
        fprintf(stderr, "Failed to find burst_rst_state\n");
        return -1;
    }
    if (clear_batch_map(burst_rst_state_fd) < 0)
        return -1;
    printf("burst_rst_state is cleared\n");

    int global_icmp_pkt_counter_fd, icmp_counter_fixed_fd, burst_icmp_state_fd;
    global_icmp_pkt_counter_fd = bpf_object__find_map_fd_by_name(obj, "global_icmp_pkt_counter");
    if (global_icmp_pkt_counter_fd < 0) {
        fprintf(stderr, "Failed to find global_icmp_pkt_counter\n");
        return -1;
    }
    if (clear_pkt_counter_map(global_icmp_pkt_counter_fd) < 0)
        return -1;
    printf("global_icmp_pkt_counter is cleared\n");

    icmp_counter_fixed_fd = bpf_object__find_map_fd_by_name(obj, "icmp_counter_fixed");
    if (icmp_counter_fixed_fd < 0) {
        fprintf(stderr, "Failed to find icmp_counter_fixed\n");
        return -1;
    }
    if (clear_batch_map(icmp_counter_fixed_fd) < 0)
        return -1;
    printf("icmp_counter_fixed is cleared\n");

    burst_icmp_state_fd = bpf_object__find_map_fd_by_name(obj, "burst_icmp_state");
    if (burst_icmp_state_fd < 0) {
        fprintf(stderr, "Failed to find burst_icmp_state\n");
        return -1;
    }
    if (clear_batch_map(burst_icmp_state_fd) < 0)
        return -1;
    printf("burst_icmp_state is cleared\n");

    int global_udp_pkt_counter_fd, udp_counter_fixed_fd, burst_udp_state_fd;
    global_udp_pkt_counter_fd = bpf_object__find_map_fd_by_name(obj, "global_udp_pkt_counter");
    if (global_udp_pkt_counter_fd < 0) {
        fprintf(stderr, "Failed to find global_udp_pkt_counter\n");
        return -1;
    }
    if (clear_pkt_counter_map(global_udp_pkt_counter_fd) < 0)
        return -1;
    printf("global_udp_pkt_counter is cleared\n");

    udp_counter_fixed_fd = bpf_object__find_map_fd_by_name(obj, "udp_counter_fixed");
    if (udp_counter_fixed_fd < 0) {
        fprintf(stderr, "Failed to find udp_counter_fixed\n");
        return -1;
    }
    if (clear_batch_map(udp_counter_fixed_fd) < 0)
        return -1;
    printf("udp_counter_fixed is cleared\n");

    burst_udp_state_fd = bpf_object__find_map_fd_by_name(obj, "burst_udp_state");
    if (burst_udp_state_fd < 0) {
        fprintf(stderr, "Failed to find burst_udp_state\n");
        return -1;
    }
    if (clear_batch_map(burst_udp_state_fd) < 0)
        return -1;
    printf("burst_udp_state is cleared\n");

    int global_gre_pkt_counter_fd, gre_counter_fixed_fd, burst_gre_state_fd;
    global_gre_pkt_counter_fd = bpf_object__find_map_fd_by_name(obj, "global_gre_pkt_counter");
    if (global_gre_pkt_counter_fd < 0) {
        fprintf(stderr, "Failed to find global_gre_pkt_counter\n");
        return -1;
    }
    if (clear_pkt_counter_map(global_gre_pkt_counter_fd) < 0)
        return -1;
    printf("global_gre_pkt_counter is cleared\n");

    gre_counter_fixed_fd = bpf_object__find_map_fd_by_name(obj, "gre_counter_fixed");
    if (gre_counter_fixed_fd < 0) {
        fprintf(stderr, "Failed to find gre_counter_fixed\n");
        return -1;
    }
    if (clear_batch_map(gre_counter_fixed_fd) < 0)
        return -1;
    printf("gre_counter_fixed is cleared\n");

    burst_gre_state_fd = bpf_object__find_map_fd_by_name(obj, "burst_gre_state");
    if (burst_gre_state_fd < 0) {
        fprintf(stderr, "Failed to find burst_gre_state\n");
        return -1;
    }
    if (clear_batch_map(burst_gre_state_fd) < 0)
        return -1;
    printf("burst_gre_state is cleared\n");

    return 0;
}

int stats_fw(struct stats_config * stats)
{
    size_t vsize = sizeof(__u64) * n_cpus;
    __u64 *values = calloc(n_cpus, sizeof(__u64));

    if (stats == NULL) {
        fprintf(stderr, "stats parameter is NULL\n");
        goto error;
    }

    if (values == NULL) {
        fprintf(stderr, "Failed to calloc memory\n");
        goto error;
    }

    int global_syn_pkt_counter_map_fd, global_ack_pkt_counter_map_fd, global_rst_pkt_counter_map_fd, global_icmp_pkt_counter_map_fd, global_udp_pkt_counter_map_fd, global_gre_pkt_counter_map_fd;

    global_syn_pkt_counter_map_fd = bpf_object__find_map_fd_by_name(obj, "global_syn_pkt_counter");
    if (global_syn_pkt_counter_map_fd < 0) {
        fprintf(stderr, "Failed to find global_syn_pkt_counter eBPF map\n");
        goto error;
    }

    global_ack_pkt_counter_map_fd = bpf_object__find_map_fd_by_name(obj, "global_ack_pkt_counter");
    if (global_ack_pkt_counter_map_fd < 0) {
        fprintf(stderr, "Failed to find global_ack_pkt_counter eBPF map\n");
        goto error;
    }

    global_rst_pkt_counter_map_fd = bpf_object__find_map_fd_by_name(obj, "global_rst_pkt_counter");
    if (global_rst_pkt_counter_map_fd < 0) {
        fprintf(stderr, "Failed to find global_rst_pkt_counter eBPF map\n");
        goto error;
    }

    global_icmp_pkt_counter_map_fd = bpf_object__find_map_fd_by_name(obj, "global_icmp_pkt_counter");
    if (global_icmp_pkt_counter_map_fd < 0) {
        fprintf(stderr, "Failed to find global_icmp_pkt_counter eBPF map\n");
        goto error;
    }

    global_udp_pkt_counter_map_fd = bpf_object__find_map_fd_by_name(obj, "global_udp_pkt_counter");
    if (global_udp_pkt_counter_map_fd < 0) {
        fprintf(stderr, "Failed to find global_udp_pkt_counter eBPF map\n");
        goto error;
    }

    global_gre_pkt_counter_map_fd = bpf_object__find_map_fd_by_name(obj, "global_gre_pkt_counter");
    if (global_gre_pkt_counter_map_fd < 0) {
        fprintf(stderr, "Failed to find global_gre_pkt_counter eBPF map\n");
        goto error;
    }

    __u64 total_syn_cnt = 0;
    if (bpf_map_lookup_elem(global_syn_pkt_counter_map_fd, &key, values)) {
        fprintf(stderr, "bpf_map_lookup_elem");
        goto error;
    }
    for (int cpu = 0; cpu < n_cpus; cpu++) {
        total_syn_cnt += values[cpu];
    }

    memset(values, 0, vsize);
    __u64 total_ack_cnt = 0;
    if (bpf_map_lookup_elem(global_ack_pkt_counter_map_fd, &key, values)) {
        fprintf(stderr, "bpf_map_lookup_elem");
        goto error;
    }
    for (int cpu = 0; cpu < n_cpus; cpu++) {
        total_ack_cnt += values[cpu];
    }

    memset(values, 0, vsize);
    __u64 total_rst_cnt = 0;
    if (bpf_map_lookup_elem(global_rst_pkt_counter_map_fd, &key, values)) {
        fprintf(stderr, "bpf_map_lookup_elem");
        goto error;
    }
    for (int cpu = 0; cpu < n_cpus; cpu++) {
        total_rst_cnt += values[cpu];
    }

    memset(values, 0, vsize);
    __u64 total_icmp_cnt = 0;
    if (bpf_map_lookup_elem(global_icmp_pkt_counter_map_fd, &key, values)) {
        fprintf(stderr, "bpf_map_lookup_elem");
        goto error;
    }
    for (int cpu = 0; cpu < n_cpus; cpu++) {
        total_icmp_cnt += values[cpu];
    }

    memset(values, 0, vsize);
    __u64 total_udp_cnt = 0;
    if (bpf_map_lookup_elem(global_udp_pkt_counter_map_fd, &key, values)) {
        fprintf(stderr, "bpf_map_lookup_elem");
        goto error;
    }
    for (int cpu = 0; cpu < n_cpus; cpu++) {
        total_udp_cnt += values[cpu];
    }

    memset(values, 0, vsize);
    __u64 total_gre_cnt = 0;
    if (bpf_map_lookup_elem(global_gre_pkt_counter_map_fd, &key, values)) {
        fprintf(stderr, "bpf_map_lookup_elem");
        goto error;
    }
    for (int cpu = 0; cpu < n_cpus; cpu++) {
        total_gre_cnt += values[cpu];
    }

    stats->syn = total_syn_cnt;
    stats->ack = total_ack_cnt;
    stats->rst = total_rst_cnt;
    stats->icmp = total_icmp_cnt;
    stats->udp = total_udp_cnt;
    stats->gre = total_gre_cnt;

    return 0;

error:
    if (values) free (values);
    return -1;
}