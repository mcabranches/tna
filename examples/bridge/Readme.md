# TNA Bridge example

Please use the setup on the figure to test TNA. Currenlty, the XDP fast path is automated. We should add code to support the TC hook. To run theI suggest using 2 hosts (one runs TNA the other is the client and generates traffic). Each of the hosts has 1 NIC for management and 2 service NICs, directly connected to the NICs of the other host. In Virtual box you can connect the virtual interfaces to a "internal network" to simulate a direct connection between interfaces.

![bridge setup](./figures/bridge_example_xdp.pdf)

## Network setup scripts

* scripts/add_br_tna_host.sh -> configs the network on the TNA host

* scripts/add_br_ns_client.sh -> configs the network on the client host

## Testing 

Run TNA on the TNA machine:

    ./build/tna 

Test connectivity on the client machine: 

    ip netns exec ns1 ping 192.168.1.11