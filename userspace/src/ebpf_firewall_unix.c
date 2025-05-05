
#include <stdarg.h>
#include <strings.h>
#include <stdbool.h>
#include <ctype.h>
#include <sys/socket.h>
#include <sys/un.h>

#include <ebpf_firewall_unix.h>
#include <ebpf_firewall_common.h>


#define BUF_SZ    1024

static int srv_fd = -1;
extern int exiting;

static void reply(int cfd, const char *fmt, ...) {
    char buf[BUF_SZ];
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(buf, sizeof buf, fmt, ap);
    va_end(ap);
    if (n < 0 || n >= (int)sizeof buf || write(cfd, buf, (size_t)n) != n)
        fprintf(stderr, "short write when replying\n");
}

/* ---------- stub command handlers -------------------------------------- */

static void handle_restart_fw(int cfd, char **argv, int argc) {
    //(void)argv; (void)argc;
    restart_fw();
    reply(cfd, "OK FW restarted\n");
}

static void handle_clear_fw(int cfd, char **argv, int argc) {
    (void)argv; (void)argc;
    // TODO
    
    reply(cfd, "OK stats cleared\n");
}

static void handle_stats_fw(int cfd, char **argv, int argc) {
    (void)argv; (void)argc;
    // TODO: gather real stats
    reply(cfd, "OK SYN=0 ACK=0 RST=0 ICMP=0 UDP=0 GRE=0\n");
}

static void handle_list_ip(int cfd, char **argv, int argc) {
    (void)argv; (void)argc;
    // TODO
    reply(cfd, "OK (no IPs blacklisted yet)\n");
}

static void handle_clear_ip(int cfd, char **argv, int argc) {
    if (argc != 2) { reply(cfd, "ERR usage: CLEAR_IP <ip>\n"); return; }
    // TODO
    reply(cfd, "OK %s removed\n", argv[1]);
}

static void handle_clear_ip_all(int cfd, char **argv, int argc) {
    (void)argv; (void)argc;
    // TODO
    reply(cfd, "OK all IPs removed\n");
}

static void handle_add_ip(int cfd, char **argv, int argc) {
    if (argc < 2 || argc > 3) {
        reply(cfd, "ERR usage: ADD_IP <ip> [seconds]\n"); return;
    }
    const char *ip = argv[1];
    int secs = (argc == 3) ? atoi(argv[2]) : 600; // default 10 min
    // TODO
    reply(cfd, "OK %s blacklisted for %d s\n", ip, secs);
}

/* Table‐driven dispatch */
struct cmd_entry { const char *name; void (*fn)(int,char**,int); };
static const struct cmd_entry cmds[] = {
    {"RESTART_FW",  handle_restart_fw},
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