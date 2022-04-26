#ifndef TNABR_H
#define TNABR_H

#include <signal.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <cstdlib>
#include <stdexcept>
#include <iostream>
#include <iterator>
#include <list>
#include <linux/if_link.h>
#include "util.h"
#include "xdp_brfdb.skel.h"

using namespace std;


//add atributes related to STP and vlans
struct tna_bridge {
	char brname[16];
	list<struct tna_interface> brifs;
};



class Tnabr {
	public:
		Tnabr(int ifindex, int flags) { //constructor
			if (ifindex < 0)
				throw std::invalid_argument("tnabr: invalid interface index");
			else
				_ifindex = ifindex;
			if (flags < 0)
				throw std::invalid_argument("tnabr: invalid xdp flags");
			else
				_flags = flags;

			load_bpf();
		}

		Tnabr(int ifindex) {
			if (ifindex < 0)
				throw std::invalid_argument("tnabr: invalid interface index");
			else
				_ifindex = ifindex;

			load_bpf();
		}

		//add a destructor ~Tnabr
        ~Tnabr(void) {
            //do cleanup - need to iterate on all interfaces
			uninstall_tnabr(_ifindex);
			destroy_tnabr();
        }

		int load_bpf(void) {
			/* Load and verify BPF application */
			skel = xdp_brfdb_bpf__open();
			if (!skel) {
				throw std::runtime_error("Failed to open xdp_brfdb skel\n");
				return -1;
			}

			int err = xdp_brfdb_bpf__load(skel);
			if (err) {
				throw std::runtime_error("Failed to load and verify BPF skeleton\n");
				destroy_tnabr();
				return -2;
			}
			else
				return 0;
		}

		void showdata(void) {
			cout << _ifindex <<  endl;
			cout << _flags <<  endl;
		}

		int install_tnabr(int ifindex) {
			int err = util::install_xdp(skel->progs.xdp_pass_main, ifindex, _flags);
			if (err < 0) {
				throw std::runtime_error("Failed to install tnabr code\n");
				uninstall_tnabr(ifindex);
			}
			else {
				save_br_interfaces(ifindex);
			}
			return err;
		}

		int uninstall_tnabr(int ifindex) {
			util::uninstall_xdp(ifindex, _flags);
			del_br_interfaces(ifindex);
			return 0;
		}

		int add_tna_bridge(void) {

			return 0;
		}

		int add_if_tna_bridge(struct tna_bridge tnabridge, struct tna_interface tnainterface) {
			cout << "Adding interface " << tnainterface.ifindex << " to bridge " << tnabridge.brname << endl;
			return 0;
		}

		int remove_if_tna_bridge(struct tna_bridge tnabridge, struct tna_interface tnainterface) {
			cout << "Removing interface " << tnainterface.ifindex << " from bridge " << tnabridge.brname << endl;
			return 0;
		}

	private:
		//to-do: add an object to represent the bridge
		int ret;
		struct xdp_brfdb_bpf *skel;
		int _ifindex;
		int _flags = XDP_FLAGS_SKB_MODE; //default
		list<struct tna_bridge> tnabrs; //list of TNA accel Linux bridges

		/* Inventory for bridge interfaces */
		void save_br_interfaces(int ifindex) {
			//cout << "Adding interface " << ifindex << " to bridge bbb" << endl;
		}

		void del_br_interfaces(int ifindex) {
			//cout << "Deleting interface " << ifindex << " to bridge bbb" << endl;
		}

		int destroy_tnabr(void)
		{
			int err = 0;
			xdp_brfdb_bpf__destroy(skel);

			return err < 0 ? -err : 0;
		}
		

};
#endif