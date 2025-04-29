#!/bin/bash
xdp-loader unload -a ens38
clang -O2 -g -target bpf -c xdp_prog.c -o xdp_prog.o
gcc -o attach_xdp attach_xdp.c -lbpf -lxdp -lnetfilter_conntrack -lpthread
./attach_xdp