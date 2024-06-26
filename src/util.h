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
#include <set>
#include <iterator>
#include <unordered_map>
#include <queue>
#include <condition_variable>
#include <mutex>
#include <net/if.h>
#include <fstream>
#include <bpf/bpf.h>

#define FPM_XDP 0
#define FPM_TC 1 

using namespace std;

struct tna_fpd {
	struct bpf_prog_load_attr fpm_prog_load_attr;
	struct bpf_object *fpm_bpf_obj;
	struct bpf_program *fpm_bpf_prog;
	struct bpf_map *fpm_dev_map; 
	int fpm_dev_map_fd = 0;
	int fpm_fd = 0;	
};

struct tna_vlan {
	int vid;
	int is_untagged_vlan;
};

struct tna_interface {
	int ifindex;
	int master_index;
	int is_veth;
	int fpm_set;
	int tna_event_type; //m-> topology manager should use this (see old update_tna_bridge - tnanl.h)
	int has_vlan;
	int has_l3;
	int ref_cnt;
	int ignore;
	uint8_t op_state;
	/* save vlan list for each interface on tna_bridge object */
	unordered_map<int, struct tna_vlan> vlans;
	list<string> tna_svcs; //control what is installed on each interface 
	string ifname;
	string type;
	string op_state_str;
	string mac_addr_str;
	char ip4Addr[INET_ADDRSTRLEN];
};

struct Tnaodb {
	class Tnabr *tnabr;
	class Tnartr *tnartr;
	class Tnaipt *tnaipt;
	//add other objects
	unordered_map <string, struct tna_interface> tnaifs;
	unordered_map <string, struct tna_fpd*> tnafpd;
	set<string> ignore_ifs;
};

//add atributes related to STP, l3 and vlans
struct tna_bridge {
	uint8_t op_state;
	int has_vlan;
	int has_l3;
	int has_l3_br_dev;
	int has_ipt;
	int has_untagged_vlan;
	int stp_enabled;
	string brname;
	string op_state_str;
	unordered_map<string, struct tna_interface *> brifs;
};

struct tna_rtr {
	int has_rtr_br;
	unordered_map<string, struct tna_interface *> rtrifs;
};

struct tna_event {
	int event_type;
	int event_flag;
	struct tna_interface interface;
};

/* TNA global variables */
namespace tna_g_ns {
	//signal nl events
    pthread_mutex_t m1 = PTHREAD_MUTEX_INITIALIZER;
    pthread_cond_t cv1 = PTHREAD_COND_INITIALIZER;
    int tna_event_type = 0;
	int tna_event_flag = 0;
	int tna_stop = 0;

	enum tna_event_type {
		TNA_ADD = 1,
		TNA_DEL,
		TNA_STOP
	};

	enum tna_event_flags {
		TNA_BR_EVENT = 1 << 0,
		TNA_RTR_EVENT = 1 << 1,
		TNA_IPT_EVENT = 1 << 2,
	};

    struct tna_interface interface_g = {0};

	queue<struct tna_event> tna_event_q;

    int clean_g_ns(void)
    {
        pthread_mutex_lock(&tna_g_ns::m1);
		struct tna_event event;
		event.event_type = tna_g_ns::TNA_STOP; //stop
		while (!tna_g_ns::tna_event_q.empty())
			tna_event_q.pop();
        tna_event_q.push(event);
        pthread_cond_signal(&cv1);
        pthread_mutex_unlock(&tna_g_ns::m1);
        return 0;
    }

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

	static int uninstall_tc(int ifindex, int tc_flags)
    {
		DECLARE_LIBBPF_OPTS(bpf_tc_hook, tc_hook, .ifindex = ifindex,
			    .attach_point = BPF_TC_INGRESS);
		DECLARE_LIBBPF_OPTS(bpf_tc_opts, tc_opts, .handle = 1, .priority = 1);
		int err;

		tc_opts.flags = tc_opts.prog_fd = tc_opts.prog_id = 0;
	    err = bpf_tc_detach(&tc_hook, &tc_opts);

		if (err) {
			printf("Failed to dettach TC");
		}

		bpf_tc_hook_destroy(&tc_hook);

	    return 1;
	}

	static int install_tc(struct bpf_program *tc_prog, int ifindex, int tc_flags)
    {
		DECLARE_LIBBPF_OPTS(bpf_tc_hook, tc_hook, .ifindex = ifindex,
			    .attach_point = BPF_TC_INGRESS);
		DECLARE_LIBBPF_OPTS(bpf_tc_opts, tc_opts, .handle = 1, .priority = 1);

		int err;
	    int bpf_prog_fd = bpf_program__fd(tc_prog);

		bpf_tc_hook_create(&tc_hook);

		tc_opts.prog_fd = bpf_program__fd(tc_prog);
		tc_opts.flags = 0;

		err = bpf_tc_attach(&tc_hook, &tc_opts);
		if (err) {
			printf("Failed to attach TC");
		}

		return 0;
    }

}

#endif
