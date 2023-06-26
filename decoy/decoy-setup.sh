#!/usr/bin/env bash

# en0 = enp0s8 = VirtualBox Interface: Internal Network
# en1 = enp0s3 = VirtualBox Interface: NAT

ifconfig enp0s8 up
ifconfig enp0s8 0.0.0.0

ifconfig enp0s3 up
ifconfig enp0s3 0.0.0.0

brctl addbr br0
brctl addif br0 enp0s8 enp0s3
dhclient br0

modprobe br_netfilter

sysctl -w net.bridge.bridge-nf-call-iptables=1
sysctl -w net.ipv4.ip_forward=1

iptables -A FORWARD -i br0 -s 172.217.17.32 -j NFQUEUE --queue-num 1
