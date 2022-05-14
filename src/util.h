#ifndef USER_UTIL_H
#define USER_UTIL_H

#include <bpf/libbpf.h>
#include <signal.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <cstdlib>
#include <stdexcept>
#include <iostream>
#include <linux/if_link.h>
#include <list>
#include <iterator>
#include <unordered_map>
#include <queue>
#include <condition_variable>
#include <mutex>


using namespace std;



//convert this to a class with methods to manage the attributes
//merge the two structs bellow
struct tna_interface {
	int ifindex;
	int master_index;
	uint8_t is_veth;
	uint8_t op_state;
	string ifname;
	string type;
	string op_state_str;
	string mac_addr_str;
};

//add atributes related to STP and vlans
//convert this to a class with methods to manage the attributes
struct tna_bridge {
	uint8_t op_state;
	string brname;
	string op_state_str;
	list<struct tna_interface> brifs;
};


namespace util {

    static int uninstall_xdp(int ifindex, int flags)
    {
	    bpf_xdp_attach(ifindex, -1, flags, NULL);
	    return 1;
    }

    static int install_xdp(struct bpf_program *xdp_prog, int ifindex, int xdp_flags)
    {
	    int bpf_prog_fd = bpf_program__fd(xdp_prog);

	    if (bpf_xdp_attach(ifindex, bpf_prog_fd, xdp_flags, NULL) < 0) {
			printf("Error linking fd to xdp with offload flags\n");
			return -1;
	    }
	    else {
		    printf("XDP program loaded\n");
	    }

	return 0;
    }
}

#endif