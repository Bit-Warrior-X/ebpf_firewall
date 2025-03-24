xdp-loader unload -a ens38

clang -O2 -target bpf -c xdp_prog.c -o xdp_prog.o

gcc -o attach_xdp attach_xdp.c -lbpf -lxdp
