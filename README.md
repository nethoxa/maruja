# Maruja

A lightweight Linux kernel module for runtime IP blocking using Netfilter. Intercepts incoming IPv4 packets at `NF_INET_PRE_ROUTING` and drops those matching a user-defined blocklist. Rules are managed at runtime through the `maruja` CLI. The device node (`/dev/maruja`) is created automatically via udev.

## Demo

https://github.com/erebus-eth/maruja/assets/135072738/bcf61fe8-e5b4-43bb-942a-dd25a9ea40bf

## Prerequisites

- Linux kernel headers (`linux-headers-$(uname -r)`)
- Make
- GCC

## Usage

```bash
# Build the module
./maruja compile

# Load (default max 10 rules)
./maruja install

# Load with custom rule limit
./maruja install 50

# Block an IP
./maruja block 192.168.1.100

# Unblock an IP
./maruja unblock 192.168.1.100

# List active rules
./maruja list

# View kernel log
./maruja log

# Unload
./maruja uninstall
```
