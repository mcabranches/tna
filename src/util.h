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
#include <net/if.h>
#include <fstream>


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
	int tna_event_type; //m-> topology manager should use this (see old update_tna_bridge - tnanl.h)
	int has_vlan;
	int ref_cnt; //To-do: control if interface is referenced by any TNAs service 
	/* save vlan list for each interface on tna_bridge object */
	uint8_t op_state;
	unordered_map<int, struct tna_vlan> vlans;
	list<string> tna_svcs; //control what is installed on each interface 
	string ifname;
	string type;
	string op_state_str;
	string mac_addr_str;
};

struct Tnaodb {
	class Tnabr *tnabr;
	//add other objects
	unordered_map <string, struct tna_interface> tnaifs;
};

//add atributes related to STP and vlans
struct tna_bridge {
	uint8_t op_state;
	int has_vlan;
	int has_untagged_vlan;
	int stp_enabled;
	string brname;
	string op_state_str;
	unordered_map<string, struct tna_interface *> brifs; //change this to a pointer to tnaodb interfaces
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
