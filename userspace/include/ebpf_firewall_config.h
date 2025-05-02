#ifndef EBPF_FIREWALL_CONFIG_H
#define EBPF_FIREWALL_CONFIG_H

int init_time_offset(void);
int load_config(struct bpf_object *obj);

#endif