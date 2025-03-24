// attach_xdp.c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <net/if.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

int main(int argc, char **argv) {
    const char *ifname = "enp1s0";  // Replace with your interface name if needed
    int ifindex, err;
    struct bpf_object *obj;
    struct bpf_program *prog_main, *prog_parse_syn, *prog_parse_ack;
    int prog_main_fd, prog_parse_syn_fd, prog_parse_ack_fd;
    int prog_array_map_fd;
    
    // Get interface index.
    ifindex = if_nametoindex(ifname);
    if (!ifindex) {
        fprintf(stderr, "ERROR: if_nametoindex(%s) failed\n", ifname);
        return 1;
    }
    
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
    
    // Find program sections.
    prog_main = bpf_object__find_program_by_name(obj, "xdp_main");
    prog_parse_syn = bpf_object__find_program_by_name(obj, "xdp_parse_syn");
    prog_parse_ack = bpf_object__find_program_by_name(obj, "xdp_parse_ack_rst");
    if (!prog_main || !prog_parse_syn || !prog_parse_ack) {
        fprintf(stderr, "ERROR: could not find all program sections\n");
        goto cleanup;
    }
    
    // Get file descriptors for the programs.
    prog_main_fd = bpf_program__fd(prog_main);
    prog_parse_syn_fd = bpf_program__fd(prog_parse_syn);
    prog_parse_ack_fd = bpf_program__fd(prog_parse_ack);
    
    // Find the prog_array map (declared as "prog_array" in our BPF program).
    struct bpf_map *map = bpf_object__find_map_by_name(obj, "prog_array");
    if (!map) {
        fprintf(stderr, "ERROR: could not find prog_array map\n");
        goto cleanup;
    }
    prog_array_map_fd = bpf_map__fd(map);
    
    // Update the prog_array map:
    // Key 0 -> xdp_parse_syn; Key 1 -> xdp_parse_ack_rst.
    int key0 = 0, key1 = 1;
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
    
    // Attach the main XDP program to the interface.
    err = bpf_xdp_attach(ifindex, prog_main_fd, 0, NULL);
    if (err < 0) {
        fprintf(stderr, "ERROR: attaching XDP program to %s (ifindex %d) failed: %d\n", ifname, ifindex, err);
        goto cleanup;
    }
    
    printf("XDP program successfully attached to interface %s (ifindex %d)\n", ifname, ifindex);
    printf("Press Ctrl+C to exit and detach the program.\n");
    
    // Wait until terminated.
    while (1)
        sleep(1);
    
cleanup:
    // Detach the XDP program before exit.
    bpf_xdp_detach(ifindex, 0, NULL);
    if (obj)
        bpf_object__close(obj);
    
    return err < 0 ? -err : 0;
}
