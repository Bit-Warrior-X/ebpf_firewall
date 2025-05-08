#ifndef EBPF_FIREWALL_CORE_H
#define EBPF_FIREWALL_CORE_H

int restart_fw();
int clear_fw();
int stats_fw(struct stats_config * stats);
int list_ip(char **out);
int clear_ip(char * ip);
int clear_ip_all();
int add_ip(char *ip, int seconds);

#endif