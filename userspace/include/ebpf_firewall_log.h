#ifndef EBPF_FIREWALL_LOG_H
#define EBPF_FIREWALL_LOG_H

void print_firewall_status(struct tm * tm_info, int reason, __u32 srcip);

#endif