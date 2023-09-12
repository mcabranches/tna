#!/bin/bash

#config bridges
brctl addbr br0
brctl addbr br1
brctl addif br0 enp0s8
brctl addif br1 enp0s9
ifconfig enp0s8 up
ifconfig enp0s9 up
ifconfig br0 up
ifconfig br1 up
brctl stp br0 on #may comment if not using STP
brctl stp br1 on #may comment if not using STP

#Add NS, veths and connect them to the bridges
#NS1
ip netns add ns1
ip link add veth11 type veth peer name veth12
ip link set veth12 netns ns1
ip netns exec ns1 ip link set lo up
ip netns exec ns1 ip addr add 192.168.1.20/24 dev veth12
ip netns exec ns1 ip link set veth12 up
ip link set veth11 up
brctl addif br0 veth11
#NS2
ip netns add ns2
ip link add veth21 type veth peer name veth22
ip link set veth22 netns ns2
ip netns exec ns2 ip link set lo up
ip netns exec ns2 ip addr add 192.168.1.11/24 dev veth22
ip netns exec ns2 ip link set veth22 up
ip link set veth21 up
brctl addif br1 veth21