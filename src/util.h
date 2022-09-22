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

struct tna_vlan {
	int vid;
	int is_untagged_vlan;
};


struct tna_interface {
	int ifindex;
	int master_index;
	int is_veth;
	int xdp_set;
	/* save vlan list for each interface on tna_bridge object */
	unordered_map<int, struct tna_vlan> vlans;
	uint8_t op_state;
	string ifname;
	string type;
	string op_state_str;
	string mac_addr_str;
};

//add atributes related to STP and vlans
struct tna_bridge {
	uint8_t op_state;
	string brname;
	string op_state_str;
	int has_vlan;
	int has_untagged_vlan;
	unordered_map<string, struct tna_interface> brifs;
};

/* TNA global variables */
namespace tna_g_ns {
	//signal nl events
    pthread_mutex_t m1 = PTHREAD_MUTEX_INITIALIZER;
    pthread_cond_t cv1 = PTHREAD_COND_INITIALIZER;
    int tna_event_type = 0;
	int tna_event_flag = 0;

    struct tna_interface interface_g = {0};

    int clean_g_ns(void)
    {
        pthread_mutex_lock(&tna_g_ns::m1);
        tna_event_type = 1;
        pthread_cond_signal(&cv1);
        pthread_mutex_unlock(&tna_g_ns::m1);

        return 0;
    }

	enum tna_event_flags {
		TNA_BR_EVENT = 1 << 0,
		TNA_IPT_EVENT = 1 << 1,
	};
}


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