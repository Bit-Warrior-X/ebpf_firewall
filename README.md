# eBPF Firewall

A high-performance Linux kernel-based anti-DDoS firewall leveraging XDP (eXpress Data Path) and eBPF (extended Berkeley Packet Filter) technology.

## Overview

eBPF Firewall is designed to detect and mitigate various network flood attacks directly in the Linux kernel, providing exceptional performance with minimal overhead. By operating at the XDP layer, it can process packets before they reach the regular network stack, making it highly efficient for DDoS protection.

## Features

- **High Performance**: Operates at the XDP layer for efficient packet processing
- **Multiple Attack Vector Protection**:
  - TCP SYN flood protection
  - TCP ACK flood protection
  - TCP RST flood protection
  - ICMP flood protection
  - UDP flood protection
  - GRE flood protection
- **Intelligent Detection Mechanisms**:
  - Rate limiting
  - Burst detection
  - Fixed window thresholds
- **Automatic IP Blocking**: Temporarily blocks malicious sources
- **Configurable**: Easy customization via configuration file
- **Minimal Resource Usage**: Operates in the kernel without userspace packet handling

## Requirements

- Linux kernel 5.10+ (with XDP support)
- LLVM and Clang for compiling eBPF programs
- libxdp-dev
- libbpf-dev
- libnetfilter-conntrack-dev

## Installation

1. Ensure you have the required dependencies:
   ```bash
   apt install clang llvm libelf-dev libbpf-dev xdp-tools libnetfilter-conntrack-dev
   ```

2. Clone the repository:
   ```bash
   git clone https://github.com/bit-warrior-x/ebpf_firewall.git
   cd ebpf_firewall
   ```

3. Configure the firewall by editing `firewall.config`:
   ```bash
   nano firewall.config
   ```

4. Build and attach the XDP program:
   ```bash
   make run
   ```

## Configuration

The `firewall.config` file allows customization of various parameters:

Becareful! Firewaill use `build/firewall.config`

```
#------------------GLOBAL-------------------
dev = eth0                    # Network interface to attach to
attach_mode = drv            # XDP attachment mode (skb, native, drv, hw)
black_ip_duration = 3600     # Duration in seconds to block malicious IPs

#------------------SYN-----------------------
syn_threshold = 200000       # Packets per second threshold
syn_burst_pkt = 20           # Packets per burst threshold
syn_burst_count_per_sec = 10 # Burst count threshold per second
syn_fixed_threshold = 2000   # Fixed window threshold
syn_fixed_check_duration = 15 # Fixed window duration in seconds
challenge_timeout = 3        # SYN challenge timeout

# ... similar configurations for ACK, RST, ICMP, UDP, and GRE
```

## How It Works

The firewall operates using eBPF programs attached to the XDP hook, which intercept packets at the earliest possible point in the network stack. Key components:

1. **Packet Inspection**: Analyzes incoming packets for suspicious patterns
2. **Rate Limiting**: Tracks packet rates from source IPs
3. **Burst Detection**: Identifies traffic bursts characteristic of DDoS attacks
4. **Blocking Mechanism**: Temporarily blocks IPs identified as attack sources

Each attack vector (SYN, ACK, RST, ICMP, UDP, GRE) has dedicated detection and mitigation logic.

## Cli commands to manage firewall

Available cli commands are:
```bash
RESTART_FW : Restart the firewall
RELOAD_FW : Reload the firewall config
CLEAR_FW : Clear all packet statistics. (Reset all statistics as zero).
STATS_FW : Display all packet information captured. (SYN, ACK, RST, ICMP UDP, GRE)
LIST_IP : Dump current blacklist ip. (ip expire_ns per line)
CLEAR_IP <ip> : Remove ip from blacklist.
CLEAR_IP_ALL : Remove all ips from blacklist.
ADD_IP <ip> [seconds] : Add ip to blacklist. Default duration if seconds omitted.
```

Example Cli command Usage :
```bash
root@:# ./ebpf_firewall_cli RELOAD_FW
OK! Config reloaded
```

## License

This project is licensed under the GPL License - see the LICENSE file for details.

## Contributing

Contributions welcome! Please feel free to submit a Pull Request.
