/*
 * Test for the filter API
 * sudo iptables -A INPUT -m conntrack --ctstate NEW,ESTABLISHED,RELATED -j ACCEPT
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <errno.h>
#include <libnetfilter_conntrack/libnetfilter_conntrack.h>

struct tcp_session {
    __u32 src_ip;    // in network byte order
    __u16 src_port;  // in network byte order
    __u32 dst_ip;    // in network byte order
    __u16 dst_port;  // in network byte order
} __attribute__((packed));

static int event_cb(enum nf_conntrack_msg_type type,
                    struct nf_conntrack *ct,
                    void *data)
{
    struct tcp_session session = {0};
    __u8 value = 1;
    int err;
    //int sessions_map_fd = *(int*)data;

    /* Only handle TCP connections.
     * Use nfct_get_attr_u8() to retrieve the protocol.
     */
    uint8_t proto = nfct_get_attr_u8(ct, ATTR_ORIG_L4PROTO);
    if (proto != IPPROTO_TCP)
        return NFCT_CB_CONTINUE;
    
    uint8_t tcp_state = nfct_get_attr_u8(ct, ATTR_TCP_STATE);
    
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

    //char buf[1024];
    //nfct_snprintf(buf, sizeof(buf), ct, type, NFCT_O_DEFAULT, 0);
    //printf("### Conntrack event: %s\n", buf);

    switch (type) {
    case NFCT_T_NEW:
        //printf("--type is NFCT_T_NEW\n");
        break;
    case NFCT_T_UPDATE:
        printf("Type is NFCT_T_UPDATE\n");
        /* Update the BPF sessions map with the session key.
         * Here we use the global sessions_map_fd that was obtained during initialization.
         */
        //err = bpf_map_update_elem(sessions_map_fd, &session, &value, BPF_ANY);
        //if (err) {
        //    fprintf(stderr, "--Failed to update session map: %d\n", err);
        //}
        if (tcp_state == 3) { //Established
            printf("TCPSTATE %d (%X:%d -> %X:%d)\n", tcp_state, htonl(session.src_ip), htons(session.src_port), htonl(session.dst_ip), htons(session.dst_port));
        }
        break;
    case NFCT_T_DESTROY:
        printf("@@type is NFCT_T_DESTROY\n");
        printf("TCPSTATE %d (%X:%d -> %X:%d)\n", tcp_state, htonl(session.src_ip), htons(session.src_port), htonl(session.dst_ip), htons(session.dst_port));
        //bpf_map_delete_elem(sessions_map_fd, &session);
        break;
    default:
        //printf("--type is Unkown %d\n", type);
        break;
    }

    return NFCT_CB_CONTINUE;
}

int main(void)
{
    int i, ret;
    struct nfct_handle *h;
    struct nfct_filter *filter;

    // First dump existing connections
    h = nfct_open(CONNTRACK, 0);
    if (!h) {
        perror("nfct_open");
        return -1;
    }
    
    nfct_callback_register(h, NFCT_T_ALL, event_cb, NULL);
    printf("Existing connections:\n");

    static const int family = AF_INET;

    nfct_query(h, NFCT_Q_DUMP, &family);
    nfct_close(h);


    h = nfct_open(CONNTRACK, NFCT_ALL_CT_GROUPS);
    if (!h) {
        perror("nfct_open");
        return 0;
    }

    nfct_callback_register(h, NFCT_T_ALL, event_cb, NULL);
    ret = nfct_catch(h);
    printf("test ret=%d (%s)\n", ret, strerror(errno));

    return EXIT_SUCCESS;
}