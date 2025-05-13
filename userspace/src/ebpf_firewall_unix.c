
#include <stdarg.h>
#include <strings.h>
#include <stdbool.h>
#include <ctype.h>
#include <sys/socket.h>
#include <sys/un.h>

#include <ebpf_firewall_common.h>
#include <ebpf_firewall_unix.h>
#include <ebpf_firewall_core.h>



static int srv_fd = -1;
extern int exiting;

#define BUF_SZ    1024
#if 0
static void reply(int cfd, const char *fmt, ...) {
    char buf[BUF_SZ];
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(buf, sizeof buf, fmt, ap);
    va_end(ap);
    if (n < 0 || n >= (int)sizeof buf || write(cfd, buf, (size_t)n) != n)
        fprintf(stderr, "short write when replying\n");
}
#endif

static void reply(int cfd, const char *fmt, ...)
{
    char   stack_buf[BUF_SZ];
    char  *out      = stack_buf;   /* will point to the final buffer */
    size_t out_sz   = BUF_SZ;      /* size of *out */
    int    need;                   /* bytes required (without '\0') */

    /* ------------ first try to format into the stack buffer ------------ */
    va_list ap, ap2;
    va_start(ap, fmt);
    va_copy(ap2, ap);              /* we may need a second pass */

    need = vsnprintf(stack_buf, out_sz, fmt, ap);
    if (need < 0) {                /* encoding error */
        va_end(ap); va_end(ap2);
        fprintf(stderr, "vsnprintf failed in reply()\n");
        return;
    }
    if ((size_t)need >= out_sz) {  /* buffer too small → allocate */
        out_sz = (size_t)need + 1;             /* +1 for terminator */
        out = malloc(out_sz);
        if (!out) {
            va_end(ap); va_end(ap2);
            fprintf(stderr, "reply: OOM\n");
            return;
        }
        /* re‑format with the copied va_list */
        need = vsnprintf(out, out_sz, fmt, ap2);
    }
    va_end(ap); va_end(ap2);

    /* ------------------ write all bytes, handling short writes --------- */
    size_t sent = 0;
    while (sent < (size_t)need) {
        ssize_t n = write(cfd, out + sent, (size_t)need - sent);
        if (n < 0) {
            if (errno == EINTR)
                continue;          /* interrupted → retry */
            fprintf(stderr, "reply: write failed: %s\n", strerror(errno));
            break;
        }
        if (n == 0) {              /* should not happen on regular fds */
            fprintf(stderr, "reply: unexpected EOF on fd %d\n", cfd);
            break;
        }
        sent += (size_t)n;
    }

    if (out != stack_buf)
        free(out);
}

/* ---------- stub command handlers -------------------------------------- */

static void handle_restart_fw(int cfd, char **argv, int argc) {
    int ret = -1;
    ret = restart_fw();
    if (ret == -1 ) {
        reply(cfd, "Failed! FW restarted failed\n");
    } else {
        reply(cfd, "OK! FW restarted\n");
    }
}

static void handle_reload_fw(int cfd, char **argv, int argc) {
    int ret = -1;
    ret = reload_fw();
    if (ret == -1 ) {
       reply(cfd, "Failed! Reload config failed\n");
    } else {
        reply(cfd, "OK! Config reloaded\n");
    }
}

static void handle_clear_fw(int cfd, char **argv, int argc) {
    int ret = -1;
    ret = clear_fw();
    if (ret == -1) {
        reply(cfd, "Failed! FW clear stats failed\n");
    } else {
        reply(cfd, "OK! FW clear stats\n");
    }
}

static void handle_stats_fw(int cfd, char **argv, int argc) {
    int ret = -1;
    struct stats_config stats_config_val = {0};
    ret = stats_fw(&stats_config_val);
    if (ret == -1) {
        reply(cfd, "Failed! FW stats failed\n");    
    } else {
        reply(cfd, "OK SYN=%d ACK=%d RST=%d ICMP=%d UDP=%d GRE=%d\n", 
            stats_config_val.syn, stats_config_val.ack, stats_config_val.rst, 
            stats_config_val.icmp, stats_config_val.udp, stats_config_val.gre);
    }
}

static void handle_list_ip(int cfd, char **argv, int argc) {
    int ret = -1;
    char * data = NULL;

    ret = list_ip(&data);
    if (ret == -1) {
        reply(cfd, "Failed! List IP is failed\n");    
    } else {
        reply(cfd, "OK\n%s\n", data);
    }
    if (data) free (data);
}


static void handle_clear_ip(int cfd, char **argv, int argc) {
    if (argc != 2) { reply(cfd, "ERR usage: CLEAR_IP <ip>\n"); return; }
    int ret = -1;

    ret = clear_ip(argv[1]);
    if (ret == 0) {
        reply(cfd, "OK %s removed\n", argv[1]);
    } else if (ret == -ENOENT){
        reply(cfd, "OK! But ip %s was not registered\n", argv[1]);
    } else {
        reply(cfd, "Failed! Clear IP %s is failed\n", argv[1]);
    }
}

static void handle_clear_ip_all(int cfd, char **argv, int argc) {
    int ret = -1;
    ret = clear_ip_all();
    if (ret == 0) {
        reply(cfd, "OK! Cleared all ips from blacklist\n", argv[1]);
    } else {
        reply(cfd, "Failed! Clear all black ips failed\n");
    }
}

static void handle_add_ip(int cfd, char **argv, int argc) {
    if (argc < 2 || argc > 3) {
        reply(cfd, "ERR usage: ADD_IP <ip> [seconds]\n"); return;
    }
    const char *ip = argv[1];
    int secs = (argc == 3) ? atoi(argv[2]) : 0; // default duration

    if (secs < 0) {
        reply(cfd, "Failed! Duration should be greater than 0 seconds\n");
        return;
    }

    int ret = -1;
    ret = add_ip(argv[1], secs);
    
    if (ret == 0)
        reply(cfd, "OK %s blacklisted for %d s\n", ip, secs);
    else if (ret == 1) {
        reply(cfd, "OK %s is overwritten and set blacklisted for %d s\n", ip, secs);
    } else {
        reply(cfd, "Failed! Add %s to blacklist is failed\n", ip);
    }
}

/* Table‐driven dispatch */
struct cmd_entry { const char *name; void (*fn)(int,char**,int); };
static const struct cmd_entry cmds[] = {
    {"RESTART_FW",  handle_restart_fw},
    {"RELOAD_FW",   handle_reload_fw},
    {"CLEAR_FW",    handle_clear_fw},
    {"STATS_FW",    handle_stats_fw},
    {"LIST_IP",     handle_list_ip},
    {"CLEAR_IP",    handle_clear_ip},
    {"CLEAR_IP_ALL",handle_clear_ip_all},
    {"ADD_IP",      handle_add_ip},
};

static void dispatch(int cfd, char *line) {
    /* Tokenize in‑place */
    char *argv[8];
    int argc = 0;
    for (char *tok = strtok(line, " \t\r\n"); tok && argc < 8; tok = strtok(NULL, " \t\r\n"))
        argv[argc++] = tok;
    if (argc == 0) return;

    for (size_t i = 0; i < sizeof cmds / sizeof *cmds; ++i) {
        if (strcasecmp(argv[0], cmds[i].name) == 0) {
            cmds[i].fn(cfd, argv, argc);
            return;
        }
    }
    reply(cfd, "ERR unknown command\n");
}

static void * unix_socket_worker(void * arg)
{
    while (!exiting) 
    {
        int cfd = accept(srv_fd, NULL, NULL);
        if (cfd == -1) { if (errno == EINTR) continue; perror("accept"); break; }

        char buf[BUF_SZ];
        ssize_t n;
        /* Handle exactly one request per connection (simple) */
        if ((n = read(cfd, buf, sizeof buf - 1)) > 0) {
            buf[n] = '\0';
            dispatch(cfd, buf);
        }
        close(cfd);
    }

    return NULL;
}

int init_unix_socket() {
    struct sockaddr_un addr = { .sun_family = AF_UNIX };
    strncpy(addr.sun_path, SOCK_PATH, sizeof addr.sun_path - 1);

    /* Clean start */
    unlink(SOCK_PATH);
    if ((srv_fd = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
        perror("socket");
        return -1;
    }

    if (bind(srv_fd, (struct sockaddr *)&addr, sizeof addr) == -1) {
        perror("bind");
        return -1;
    }

    if (listen(srv_fd, 8) == -1) {
        perror("listen");
        return -1;
    }

    pthread_t unix_socket_worker_thr;
    if (pthread_create(&unix_socket_worker_thr, NULL, unix_socket_worker, NULL) != 0) {
        perror("pthread_create for unix_socket_worker_thr");
        return -1;
    }

    return 0;
}

void close_unix_socket() {
    if (srv_fd != -1) 
        close(srv_fd);
    unlink(SOCK_PATH);
}